-- Preserve the existing shoeapp table and its records.
alter table public.shoeapp
  add column if not exists brand text,
  add column if not exists payload jsonb,
  add column if not exists updated_at timestamptz not null default now();

create unique index if not exists shoeapp_brand_uidx on public.shoeapp (brand);

create table if not exists public.shoeapp_memberships (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username ~ '^[a-z0-9._-]{3,24}$'),
  brand text not null check (brand in ('K2','아이더','WIDEANGLE','다이나핏','노르디스크','NEPA','K2 Safety','EIDER SAFETY','NEPA SAFETY')),
  created_at timestamptz not null default now()
);

-- Server-only administrator sessions. The browser receives only an opaque,
-- short-lived token; the administrator password and service key stay server-side.
create table if not exists public.shoeapp_admin_sessions (
  token_hash text primary key,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
alter table public.shoeapp_admin_sessions enable row level security;
revoke all on table public.shoeapp_admin_sessions from anon, authenticated;
grant all on table public.shoeapp_admin_sessions to service_role;

-- Throttle repeated password guesses by a salted hash of the caller IP.
create table if not exists public.shoeapp_admin_login_limits (
  ip_hash text primary key,
  failures integer not null default 0,
  blocked_until timestamptz,
  updated_at timestamptz not null default now()
);
alter table public.shoeapp_admin_login_limits enable row level security;
revoke all on table public.shoeapp_admin_login_limits from anon, authenticated;
grant all on table public.shoeapp_admin_login_limits to service_role;

create or replace function public.shoeapp_admin_login_allowed(p_ip_hash text)
returns table(allowed boolean)
language sql
security definer
set search_path = ''
as $$
  select not exists (
    select 1 from public.shoeapp_admin_login_limits
    where ip_hash = p_ip_hash and blocked_until > now()
  );
$$;
revoke all on function public.shoeapp_admin_login_allowed(text) from public, anon, authenticated;
grant execute on function public.shoeapp_admin_login_allowed(text) to service_role;

create or replace function public.shoeapp_admin_login_attempt(p_ip_hash text, p_success boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare current_failures integer;
begin
  insert into public.shoeapp_admin_login_limits (ip_hash, failures, blocked_until)
  values (p_ip_hash, 0, null)
  on conflict (ip_hash) do nothing;
  select failures into current_failures from public.shoeapp_admin_login_limits
    where ip_hash = p_ip_hash for update;
  if p_success then
    update public.shoeapp_admin_login_limits set failures = 0, blocked_until = null, updated_at = now()
      where ip_hash = p_ip_hash;
  elsif current_failures >= 4 then
    update public.shoeapp_admin_login_limits set failures = current_failures + 1,
      blocked_until = now() + interval '15 minutes', updated_at = now()
      where ip_hash = p_ip_hash;
  else
    update public.shoeapp_admin_login_limits set failures = current_failures + 1, updated_at = now()
      where ip_hash = p_ip_hash;
  end if;
end;
$$;
revoke all on function public.shoeapp_admin_login_attempt(text, boolean) from public, anon, authenticated;
grant execute on function public.shoeapp_admin_login_attempt(text, boolean) to service_role;

alter table public.shoeapp_memberships enable row level security;
revoke all on table public.shoeapp_memberships from anon, authenticated;
grant select on table public.shoeapp_memberships to authenticated;
drop policy if exists "members can view own shoeapp membership" on public.shoeapp_memberships;
create policy "members can view own shoeapp membership"
  on public.shoeapp_memberships for select to authenticated using (user_id = auth.uid());

create or replace function public.add_shoeapp_membership_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.shoeapp_memberships (user_id, username, brand)
  values (
    new.id,
    lower(new.raw_user_meta_data ->> 'username'),
    new.raw_user_meta_data ->> 'brand'
  );
  return new;
end;
$$;

drop trigger if exists on_shoeapp_user_created on auth.users;
create trigger on_shoeapp_user_created
  after insert on auth.users
  for each row execute procedure public.add_shoeapp_membership_for_new_user();

alter table public.shoeapp enable row level security;
revoke all on table public.shoeapp from anon;
grant select, insert, update on table public.shoeapp to authenticated;

drop policy if exists "shoeapp dashboard state read signed in" on public.shoeapp;
drop policy if exists "shoeapp dashboard state insert signed in" on public.shoeapp;
drop policy if exists "shoeapp dashboard state update signed in" on public.shoeapp;
drop policy if exists "shoeapp users read assigned brand" on public.shoeapp;
create policy "shoeapp users read assigned brand"
  on public.shoeapp for select to authenticated
  using (exists (select 1 from public.shoeapp_memberships m where m.user_id = auth.uid() and m.brand = shoeapp.brand));
drop policy if exists "shoeapp users insert assigned brand" on public.shoeapp;
create policy "shoeapp users insert assigned brand"
  on public.shoeapp for insert to authenticated
  with check (exists (select 1 from public.shoeapp_memberships m where m.user_id = auth.uid() and m.brand = shoeapp.brand));
drop policy if exists "shoeapp users update assigned brand" on public.shoeapp;
create policy "shoeapp users update assigned brand"
  on public.shoeapp for update to authenticated
  using (exists (select 1 from public.shoeapp_memberships m where m.user_id = auth.uid() and m.brand = shoeapp.brand))
  with check (exists (select 1 from public.shoeapp_memberships m where m.user_id = auth.uid() and m.brand = shoeapp.brand));

-- Migrate the old shared-state JSON row into brand-specific rows, keeping the original row.
with brand_list(brand) as (
  values ('K2'),('아이더'),('WIDEANGLE'),('다이나핏'),('노르디스크'),('NEPA'),('K2 Safety'),('EIDER SAFETY'),('NEPA SAFETY')
), legacy as (
  select payload from public.shoeapp where dashboard_id = 'main' limit 1
)
insert into public.shoeapp (brand, payload)
select
  b.brand,
  jsonb_build_object(
    'samples', coalesce((select jsonb_agg(x.value) from jsonb_array_elements(coalesce(l.payload->'samples','[]'::jsonb)) as x(value) where x.value->>'brand'=b.brand),'[]'::jsonb),
    'books', coalesce((select jsonb_agg(x.value) from jsonb_array_elements(coalesce(l.payload->'books','[]'::jsonb)) as x(value) where x.value->>'brand'=b.brand),'[]'::jsonb),
    'season', coalesce(l.payload->'season','""'::jsonb)
  )
from brand_list b cross join legacy l
on conflict (brand) do nothing;

insert into public.shoeapp (brand, payload)
select b.brand, '{"samples":[],"books":[],"season":""}'::jsonb
from (values ('K2'),('아이더'),('WIDEANGLE'),('다이나핏'),('노르디스크'),('NEPA'),('K2 Safety'),('EIDER SAFETY'),('NEPA SAFETY')) as b(brand)
on conflict (brand) do nothing;

-- Return only occupied times for one date. Brand users can check availability
-- across all brands without reading other brands' booking details.
create or replace function public.shoeapp_reserved_slots(p_slot_date date)
returns table(slot_time text)
language sql
stable
security definer
set search_path = ''
as $$
  select distinct b.value->>'time' as slot_time
  from public.shoeapp s
  cross join lateral jsonb_array_elements(coalesce(s.payload->'books', '[]'::jsonb)) as b(value)
  where s.brand is not null
    and (b.value->>'completed') is distinct from 'true'
    and b.value->>'date' = p_slot_date::text
    and nullif(b.value->>'time', '') is not null;
$$;
revoke all on function public.shoeapp_reserved_slots(date) from public, anon;
grant execute on function public.shoeapp_reserved_slots(date) to authenticated;

-- Serialize booking writes and reject duplicate active date/time slots across
-- brands. A transaction advisory lock closes the race between simultaneous
-- requests; completed meetings release their slot.
create or replace function public.enforce_shoeapp_booking_slot()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if jsonb_typeof(coalesce(new.payload->'books', '[]'::jsonb)) <> 'array' then
    return new;
  end if;

  perform pg_advisory_xact_lock(hashtextextended('shoeapp_booking_slots', 0));

  if exists (
    select 1
    from jsonb_array_elements(coalesce(new.payload->'books', '[]'::jsonb)) with ordinality as a(value, position)
    join jsonb_array_elements(coalesce(new.payload->'books', '[]'::jsonb)) with ordinality as b(value, position)
      on a.value->>'date' = b.value->>'date'
     and a.value->>'time' = b.value->>'time'
     and a.position < b.position
    where (a.value->>'completed') is distinct from 'true'
      and (b.value->>'completed') is distinct from 'true'
      and nullif(a.value->>'date', '') is not null
      and nullif(a.value->>'time', '') is not null
  ) then
    raise exception '이미 예약된 날짜와 시간입니다.'
      using errcode = '23505', constraint = 'shoeapp_booking_slot_unique';
  end if;

  if exists (
    select 1
    from public.shoeapp other
    cross join lateral jsonb_array_elements(coalesce(other.payload->'books', '[]'::jsonb)) as existing(value)
    join lateral jsonb_array_elements(coalesce(new.payload->'books', '[]'::jsonb)) as candidate(value)
      on candidate.value->>'date' = existing.value->>'date'
     and candidate.value->>'time' = existing.value->>'time'
    where other.brand is not null
      and other.brand is distinct from new.brand
      and (existing.value->>'completed') is distinct from 'true'
      and (candidate.value->>'completed') is distinct from 'true'
      and nullif(candidate.value->>'date', '') is not null
      and nullif(candidate.value->>'time', '') is not null
  ) then
    raise exception '이미 다른 브랜드가 예약한 날짜와 시간입니다.'
      using errcode = '23505', constraint = 'shoeapp_booking_slot_unique';
  end if;

  return new;
end;
$$;
drop trigger if exists shoeapp_booking_slot_guard on public.shoeapp;
create trigger shoeapp_booking_slot_guard
  before insert or update of payload on public.shoeapp
  for each row execute function public.enforce_shoeapp_booking_slot();
-- Repair general-member availability lookup and preserve database-side duplicate protection.
-- Brand members see occupied times only. Reservation details remain protected by RLS.
create or replace function public.shoeapp_reserved_slots(p_slot_date date)
returns table(slot_time text)
language sql
stable
security definer
set search_path = ''
as $$
  select distinct b.value->>'time' as slot_time
  from public.shoeapp s
  cross join lateral jsonb_array_elements(coalesce(s.payload->'books', '[]'::jsonb)) as b(value)
  where s.brand is not null
    and (b.value->>'completed') is distinct from 'true'
    and b.value->>'date' = p_slot_date::text
    and nullif(b.value->>'time', '') is not null;
$$;
revoke all on function public.shoeapp_reserved_slots(date) from public, anon;
grant execute on function public.shoeapp_reserved_slots(date) to authenticated;

create or replace function public.enforce_shoeapp_booking_slot()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if jsonb_typeof(coalesce(new.payload->'books', '[]'::jsonb)) <> 'array' then
    return new;
  end if;

  perform pg_advisory_xact_lock(hashtextextended('shoeapp_booking_slots', 0));

  if exists (
    select 1
    from jsonb_array_elements(coalesce(new.payload->'books', '[]'::jsonb)) with ordinality as a(value, position)
    join jsonb_array_elements(coalesce(new.payload->'books', '[]'::jsonb)) with ordinality as b(value, position)
      on a.value->>'date' = b.value->>'date'
     and a.value->>'time' = b.value->>'time'
     and a.position < b.position
    where (a.value->>'completed') is distinct from 'true'
      and (b.value->>'completed') is distinct from 'true'
      and nullif(a.value->>'date', '') is not null
      and nullif(a.value->>'time', '') is not null
  ) then
    raise exception '이미 예약된 날짜와 시간입니다.'
      using errcode = '23505', constraint = 'shoeapp_booking_slot_unique';
  end if;

  if exists (
    select 1
    from public.shoeapp other
    cross join lateral jsonb_array_elements(coalesce(other.payload->'books', '[]'::jsonb)) as existing(value)
    join lateral jsonb_array_elements(coalesce(new.payload->'books', '[]'::jsonb)) as candidate(value)
      on candidate.value->>'date' = existing.value->>'date'
     and candidate.value->>'time' = existing.value->>'time'
    where other.brand is not null
      and other.brand is distinct from new.brand
      and (existing.value->>'completed') is distinct from 'true'
      and (candidate.value->>'completed') is distinct from 'true'
      and nullif(candidate.value->>'date', '') is not null
      and nullif(candidate.value->>'time', '') is not null
  ) then
    raise exception '이미 다른 브랜드가 예약한 날짜와 시간입니다.'
      using errcode = '23505', constraint = 'shoeapp_booking_slot_unique';
  end if;

  return new;
end;
$$;
drop trigger if exists shoeapp_booking_slot_guard on public.shoeapp;
create trigger shoeapp_booking_slot_guard
  before insert or update of payload on public.shoeapp
  for each row execute function public.enforce_shoeapp_booking_slot();

notify pgrst, 'reload schema';
