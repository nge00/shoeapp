-- Make the full assignment replacement compatible with safe DELETE enforcement.
-- Allow active brand managers to own one to three brands.
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
      and (assigned.brand_count < 1 or assigned.brand_count > 3 or coalesce(p.value->>'password_hash','') = '' or coalesce(p.value->>'password_salt','') = '' or coalesce((p.value->>'must_change_password')::boolean, true))
  ) then raise exception 'Active managers need a password and one to three brands.' using errcode = '22023'; end if;

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

  delete from public.shoeapp_admin_manager_brands where true;
  insert into public.shoeapp_admin_manager_brands (brand, manager_slot)
  select a.value->>'brand', (a.value->>'manager_slot')::integer
  from jsonb_array_elements(p_assignments) as a(value);

  delete from public.shoeapp_admin_sessions where admin_role = 'manager';
end;
$$;
revoke all on function public.shoeapp_save_admin_managers(jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.shoeapp_save_admin_managers(jsonb, jsonb) to service_role;

-- Authenticated members can see all calendar entries, but only the service function can change them.


