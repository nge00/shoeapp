-- Preview-only role separation for the K2 approval app.
-- Existing administrator sessions remain final-administrator sessions.
alter table public.shoeapp_admin_sessions
  add column if not exists admin_role text not null default 'super_admin'
    check (admin_role in ('super_admin', 'manager')),
  add column if not exists manager_slot integer
    check (manager_slot between 1 and 4);

create table if not exists public.shoeapp_admin_manager_profiles (
  manager_slot integer primary key check (manager_slot between 1 and 4),
  display_name text not null,
  is_active boolean not null default false,
  password_salt text,
  password_hash text,
  password_iterations integer not null default 310000,
  must_change_password boolean not null default true,
  updated_at timestamptz not null default now(),
  check ((password_salt is null) = (password_hash is null))
);

create table if not exists public.shoeapp_admin_manager_brands (
  brand text primary key check (brand in ('K2','아이더','WIDEANGLE','다이나핏','노르디스크','NEPA','K2 Safety','EIDER SAFETY','NEPA SAFETY')),
  manager_slot integer not null references public.shoeapp_admin_manager_profiles(manager_slot) on delete cascade,
  assigned_at timestamptz not null default now()
);

insert into public.shoeapp_admin_manager_profiles (manager_slot, display_name, is_active, password_salt, password_hash, must_change_password)
values
  (1, '브랜드관리자 1', false, 'a0045ae66d5ee68799fe74dc84c9d605', '4462e0bddfbc9732335fc3452a83d8132fb95343646564fa6c86c783d7d6b299', true),
  (2, '브랜드관리자 2', false, 'e9039a6c3159c47dbdab41a454df1f95', '338a76953d0b044774758ce0ff1c4675ca04ecf677741f8c6df7ca2001de5d4b', true),
  (3, '브랜드관리자 3', false, '63c780170b0ef764f0de97577f75954d', '090e088d8d6c7be6f95bda9412977edd6148ab5acdfa7717b6cfc9aac9229cb0', true),
  (4, '브랜드관리자 4', false, '02a16aaf00d8e4710d90b13d3639cbcc', '12c348d24f1892de2d5fabe6ea954821203328265fcc9806e6e8ada368124659', true)
on conflict (manager_slot) do nothing;

create table if not exists public.shoeapp_admin_schedules (
  id text primary key,
  schedule_date date not null,
  title text not null check (length(title) between 1 and 80),
  times jsonb not null default '[]'::jsonb check (jsonb_typeof(times) = 'array'),
  brand text check (brand is null or brand in ('K2','아이더','WIDEANGLE','다이나핏','노르디스크','NEPA','K2 Safety','EIDER SAFETY','NEPA SAFETY')),
  created_by_manager_slot integer references public.shoeapp_admin_manager_profiles(manager_slot),
  updated_at timestamptz not null default now()
);
create index if not exists shoeapp_admin_schedules_date_brand_idx
  on public.shoeapp_admin_schedules (schedule_date, brand);

-- Keep manager-created schedules scoped to their brand when member accounts write bookings directly.
create or replace function public.enforce_admin_schedule_booking_conflict()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if jsonb_typeof(coalesce(new.payload->'books','[]'::jsonb)) <> 'array' then return new; end if;
  if exists (
    select 1
    from jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) booking(value)
    join public.shoeapp_admin_schedules schedule
      on schedule.schedule_date::text = booking.value->>'date'
     and (schedule.brand is null or schedule.brand = new.brand)
    cross join lateral jsonb_array_elements_text(schedule.times) slot(time)
    where new.brand is not null
      and (booking.value->>'completed') is distinct from 'true'
      and booking.value->>'time' = slot.time
      and coalesce(booking.value->>'date','') ~ '^\d{4}-\d{2}-\d{2}$'
      and nullif(booking.value->>'time','') is not null
  ) then
    raise exception '관리자 일정이 등록된 시간에는 해당 브랜드 미팅을 예약할 수 없습니다.'
      using errcode = '23505', constraint = 'shoeapp_booking_schedule_unique';
  end if;
  return new;
end;
$$;
drop trigger if exists shoeapp_admin_schedule_booking_guard on public.shoeapp;
create trigger shoeapp_admin_schedule_booking_guard
  before insert or update of payload on public.shoeapp
  for each row execute function public.enforce_admin_schedule_booking_conflict();

-- Import the duplicated legacy schedule arrays once. Missing IDs are made stable from their content.
insert into public.shoeapp_admin_schedules (id, schedule_date, title, times, brand)
select distinct on (legacy_id)
  legacy_id,
  (item.value->>'date')::date,
  left(coalesce(nullif(item.value->>'title',''), '관리자 일정'), 80),
  case when jsonb_typeof(item.value->'times') = 'array' then item.value->'times' else '[]'::jsonb end,
  null
from public.shoeapp state
cross join lateral jsonb_array_elements(coalesce(state.payload->'schedules', '[]'::jsonb)) as item(value)
cross join lateral (select coalesce(nullif(item.value->>'id',''), 'legacy-' || md5(item.value::text)) as legacy_id) ids
where state.brand is not null
  and coalesce(item.value->>'date','') ~ '^\d{4}-\d{2}-\d{2}$'
  and coalesce(item.value->>'title','관리자 일정') <> ''
order by legacy_id, state.brand
on conflict (id) do nothing;

alter table public.shoeapp_admin_manager_profiles enable row level security;
alter table public.shoeapp_admin_manager_brands enable row level security;
alter table public.shoeapp_admin_schedules enable row level security;
revoke all on table public.shoeapp_admin_manager_profiles from public, anon, authenticated;
revoke all on table public.shoeapp_admin_manager_brands from public, anon, authenticated;
revoke all on table public.shoeapp_admin_schedules from public, anon, authenticated;
grant all on table public.shoeapp_admin_manager_profiles to service_role;
grant all on table public.shoeapp_admin_manager_brands to service_role;
grant all on table public.shoeapp_admin_schedules to service_role;
grant select on table public.shoeapp_admin_schedules to authenticated;
drop policy if exists "signed in users can view calendar schedules" on public.shoeapp_admin_schedules;
create policy "signed in users can view calendar schedules"
  on public.shoeapp_admin_schedules for select to authenticated using (true);

-- The edge function calls this transaction after validating the final administrator session.
create or replace function public.shoeapp_save_admin_managers(p_profiles jsonb, p_assignments jsonb)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  profile_count integer;
  assignment_count integer;
begin
  if coalesce(auth.jwt()->>'role','') <> 'service_role' then
    raise exception 'Only the trusted admin function may change manager access.' using errcode = '42501';
  end if;
  if jsonb_typeof(p_profiles) <> 'array' or jsonb_array_length(p_profiles) <> 4
     or jsonb_typeof(p_assignments) <> 'array' then
    raise exception 'Manager configuration is invalid.' using errcode = '22023';
  end if;
  select count(distinct (p.value->>'manager_slot')::integer) into profile_count
  from jsonb_array_elements(p_profiles) as p(value)
  where p.value->>'manager_slot' ~ '^[1-4]$';
  if profile_count <> 4 then
    raise exception 'All four manager profiles must be supplied.' using errcode = '22023';
  end if;
  select count(*) into assignment_count from jsonb_array_elements(p_assignments) as a(value);
  if assignment_count > 12 then
    raise exception 'A manager can be assigned at most three brands.' using errcode = '22023';
  end if;
  if exists (
    select 1 from jsonb_array_elements(p_assignments) as a(value)
    where coalesce(a.value->>'manager_slot','') !~ '^[1-4]$'
       or coalesce(a.value->>'brand','') not in ('K2','아이더','WIDEANGLE','다이나핏','노르디스크','NEPA','K2 Safety','EIDER SAFETY','NEPA SAFETY')
  ) then raise exception 'A brand assignment is invalid.' using errcode = '22023'; end if;
  if exists (
    select 1 from jsonb_array_elements(p_assignments) as a(value)
    group by a.value->>'brand' having count(*) > 1
  ) then raise exception 'A brand can only be assigned to one manager.' using errcode = '23505'; end if;
  if exists (
    select 1 from jsonb_array_elements(p_profiles) as p(value)
    left join lateral (
      select count(*) as brand_count
      from jsonb_array_elements(p_assignments) as a(value)
      where a.value->>'manager_slot' = p.value->>'manager_slot'
    ) assigned on true
    where coalesce((p.value->>'is_active')::boolean, false)
      and (assigned.brand_count < 2 or assigned.brand_count > 3 or coalesce(p.value->>'password_hash','') = '' or coalesce(p.value->>'password_salt','') = '' or coalesce((p.value->>'must_change_password')::boolean, true))
  ) then raise exception 'Active managers need a password and two or three brands.' using errcode = '22023'; end if;

  perform pg_advisory_xact_lock(hashtextextended('shoeapp_manager_access', 0));
  insert into public.shoeapp_admin_manager_profiles
    (manager_slot, display_name, is_active, password_salt, password_hash, password_iterations, must_change_password, updated_at)
  select (p.value->>'manager_slot')::integer, '브랜드관리자 ' || (p.value->>'manager_slot'),
         coalesce((p.value->>'is_active')::boolean, false), nullif(p.value->>'password_salt',''),
         nullif(p.value->>'password_hash',''), 310000,
         coalesce((p.value->>'must_change_password')::boolean, true), now()
  from jsonb_array_elements(p_profiles) as p(value)
  on conflict (manager_slot) do update set
    display_name = excluded.display_name, is_active = excluded.is_active,
    password_salt = excluded.password_salt, password_hash = excluded.password_hash,
    password_iterations = excluded.password_iterations,
    must_change_password = excluded.must_change_password, updated_at = now();

  delete from public.shoeapp_admin_manager_brands;
  insert into public.shoeapp_admin_manager_brands (brand, manager_slot)
  select a.value->>'brand', (a.value->>'manager_slot')::integer
  from jsonb_array_elements(p_assignments) as a(value);

  delete from public.shoeapp_admin_sessions where admin_role = 'manager';
end;
$$;
revoke all on function public.shoeapp_save_admin_managers(jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.shoeapp_save_admin_managers(jsonb, jsonb) to service_role;

-- Authenticated members can see all calendar entries, but only the service function can change them.
drop function if exists public.shoeapp_reserved_slots(date);
create or replace function public.shoeapp_reserved_slots(p_slot_date date, p_brand text default null)
returns table(slot_time text)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then return; end if;
  return query
    select distinct slots.slot_time from (
      select b.value->>'time' as slot_time
      from public.shoeapp s
      cross join lateral jsonb_array_elements(coalesce(s.payload->'books','[]'::jsonb)) b(value)
      where s.brand is not null and (b.value->>'completed') is distinct from 'true'
        and b.value->>'date' = p_slot_date::text and nullif(b.value->>'time','') is not null
      union all
      select t.value as slot_time
      from public.shoeapp_admin_schedules schedule
      cross join lateral jsonb_array_elements_text(schedule.times) t(value)
      where schedule.schedule_date = p_slot_date
        and (schedule.brand is null or schedule.brand = p_brand)
        and nullif(t.value,'') is not null
      union all
      select t.value #>> '{}' as slot_time
      from public.shoeapp s
      cross join lateral jsonb_array_elements(coalesce(s.payload->'schedules','[]'::jsonb)) e(value)
      cross join lateral jsonb_array_elements_text(coalesce(e.value->'times','[]'::jsonb)) t(value)
      where s.brand is not null and e.value->>'date' = p_slot_date::text and nullif(t.value #>> '{}','') is not null
    ) slots;
end;
$$;
revoke all on function public.shoeapp_reserved_slots(date, text) from public, anon;
grant execute on function public.shoeapp_reserved_slots(date, text) to authenticated;

notify pgrst, 'reload schema';
