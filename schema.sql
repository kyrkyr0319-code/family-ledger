
begin;
create schema if not exists ledger_private;
revoke all on schema ledger_private from public;
grant usage on schema ledger_private to authenticated;
create table public.ledger_families(id uuid primary key default gen_random_uuid(),owner_id uuid not null references auth.users(id),revision bigint not null default 0);
create table public.ledger_members(user_id uuid primary key references auth.users(id),family_id uuid not null references public.ledger_families(id),display_name text not null check(length(trim(display_name)) between 1 and 40));
create index on public.ledger_members(family_id);
create table public.ledger_invites(family_id uuid primary key references public.ledger_families(id),code text not null unique,expires_at timestamptz not null);
create table public.ledger_entries(
id uuid primary key default gen_random_uuid(),family_id uuid not null references public.ledger_families(id),user_id uuid not null references auth.users(id),
transaction_date date not null,type text not null check(type in ('income','expense')),
amount bigint not null check(amount between 1 and 999999999999),
category text not null,description text not null default '' check(length(description)<=500),
created_at timestamptz not null default now(),updated_at timestamptz not null default now(),
check((type='income' and category in ('급여','기타수입')) or (type='expense' and category in ('식비','생활용품','교통','주거·공과금','교육','의료','기타지출'))));
create index on public.ledger_entries(family_id,transaction_date);
alter table public.ledger_families enable row level security;
alter table public.ledger_members enable row level security;
alter table public.ledger_invites enable row level security;
alter table public.ledger_entries enable row level security;
create function ledger_private.my_family() returns uuid language sql stable security definer set search_path='' as $$
select family_id from public.ledger_members where user_id=(select auth.uid()) and auth.uid() is not null $$;
revoke all on function ledger_private.my_family() from public;
grant execute on function ledger_private.my_family() to authenticated;
create policy family_read on public.ledger_families for select to authenticated using(id=(select ledger_private.my_family()));
create policy members_read on public.ledger_members for select to authenticated using(family_id=(select ledger_private.my_family()));
create policy invites_read on public.ledger_invites for select to authenticated using(exists(select 1 from public.ledger_families f where f.id=family_id and f.owner_id=(select auth.uid())));
create policy entries_read on public.ledger_entries for select to authenticated using(family_id=(select ledger_private.my_family()));
create policy entries_add on public.ledger_entries for insert to authenticated with check(family_id=(select ledger_private.my_family()) and user_id=(select auth.uid()));
create policy entries_edit on public.ledger_entries for update to authenticated using(family_id=(select ledger_private.my_family()) and user_id=(select auth.uid())) with check(family_id=(select ledger_private.my_family()) and user_id=(select auth.uid()));
create policy entries_delete on public.ledger_entries for delete to authenticated using(family_id=(select ledger_private.my_family()) and user_id=(select auth.uid()));
revoke all on public.ledger_families,public.ledger_members,public.ledger_invites,public.ledger_entries from anon,authenticated;
grant select on public.ledger_families,public.ledger_members,public.ledger_invites,public.ledger_entries to authenticated;
grant insert(id,family_id,user_id,transaction_date,type,amount,category,description),update(transaction_date,type,amount,category,description),delete on public.ledger_entries to authenticated;
create function ledger_private.manage(action text,invite_code text default null) returns uuid language plpgsql security definer set search_path='' as $$
declare u uuid:=auth.uid(); f uuid; n text;
begin
if u is null then raise exception '로그인이 필요합니다'; end if;
perform pg_advisory_xact_lock(hashtextextended(u::text,0));
select family_id into f from public.ledger_members where user_id=u;
if action in ('create','join') then
if f is not null then raise exception '이미 가족 가계부에 참여했습니다'; end if;
select coalesce(nullif(trim(raw_user_meta_data->>'display_name'),''),'가족') into n from auth.users where id=u;
n:=left(n,40);
if action='create' then
insert into public.ledger_families(owner_id) values(u) returning id into f;
insert into public.ledger_invites values(f,encode(extensions.gen_random_bytes(24),'hex'),now()+interval '7 days');
else
select family_id into f from public.ledger_invites where code=trim(invite_code) and expires_at>now() for share;
if f is null then raise exception '초대 코드가 잘못되었거나 만료되었습니다'; end if;
end if;
insert into public.ledger_members values(u,f,n);
elsif action='renew' then
if f is null or not exists(select 1 from public.ledger_families where id=f and owner_id=u) then raise exception '생성자만 재발급할 수 있습니다'; end if;
update public.ledger_invites set code=encode(extensions.gen_random_bytes(24),'hex'),expires_at=now()+interval '7 days' where family_id=f;
else raise exception '지원하지 않는 작업'; end if;
return f;
end $$;
revoke all on function ledger_private.manage(text,text) from public;
grant execute on function ledger_private.manage(text,text) to authenticated;
create function public.ledger_manage(action text,invite_code text default null) returns uuid language sql security invoker set search_path='' as $$select ledger_private.manage(action,invite_code)$$;
revoke all on function public.ledger_manage(text,text) from public;
grant execute on function public.ledger_manage(text,text) to authenticated;
create function ledger_private.entry_guard() returns trigger language plpgsql set search_path='' as $$
begin
if new.family_id<>old.family_id or new.user_id<>old.user_id or new.id<>old.id then raise exception '소유 정보를 변경할 수 없습니다'; end if;
new.updated_at:=now();return new;
end $$;
create trigger ledger_guard before update on public.ledger_entries for each row execute function ledger_private.entry_guard();
create function ledger_private.notify_change() returns trigger language plpgsql security definer set search_path='' as $$
begin
if auth.uid() is null then raise exception '로그인이 필요합니다'; end if;
update public.ledger_families set revision=revision+1 where id=coalesce(new.family_id,old.family_id);
return null;
end $$;
revoke all on function ledger_private.entry_guard(),ledger_private.notify_change() from public;
create trigger ledger_changed after insert or update or delete on public.ledger_entries for each row execute function ledger_private.notify_change();
alter publication supabase_realtime add table public.ledger_families;
commit;