-- Approval meeting calendar schedules: slots are shared across brands and editable only by the admin service.
create or replace function public.shoeapp_reserved_slots(p_slot_date date)
returns table(slot_time text)
language sql stable security definer set search_path = '' as $$
  select distinct slots.slot_time from (
    select b.value->>'time' as slot_time
    from public.shoeapp s cross join lateral jsonb_array_elements(coalesce(s.payload->'books','[]'::jsonb)) b(value)
    where s.brand is not null and (b.value->>'completed') is distinct from 'true'
      and b.value->>'date'=p_slot_date::text and nullif(b.value->>'time','') is not null
    union all
    select t.value #>> '{}' as slot_time
    from public.shoeapp s cross join lateral jsonb_array_elements(coalesce(s.payload->'schedules','[]'::jsonb)) e(value)
      cross join lateral jsonb_array_elements_text(coalesce(e.value->'times','[]'::jsonb)) t(value)
    where s.brand is not null and e.value->>'date'=p_slot_date::text and nullif(t.value #>> '{}','') is not null
  ) slots;
$$;
revoke all on function public.shoeapp_reserved_slots(date) from public, anon;
grant execute on function public.shoeapp_reserved_slots(date) to authenticated;

create or replace function public.enforce_shoeapp_booking_slot()
returns trigger language plpgsql set search_path = '' as $$
begin
  if tg_op='UPDATE' and coalesce(auth.role(),'') <> 'service_role'
     and coalesce(new.payload->'schedules','[]'::jsonb) is distinct from coalesce(old.payload->'schedules','[]'::jsonb) then
    raise exception '관리자만 관리 일정을 변경할 수 있습니다.' using errcode='42501';
  end if;
  if tg_op='INSERT' and coalesce(auth.role(),'') <> 'service_role'
     and coalesce(new.payload->'schedules','[]'::jsonb) <> '[]'::jsonb then
    raise exception '관리자만 관리 일정을 등록할 수 있습니다.' using errcode='42501';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('shoeapp_booking_slots',0));
  if exists (
    select 1 from jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) with ordinality a(value,pos)
    join jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) with ordinality b(value,pos)
      on a.value->>'date'=b.value->>'date' and a.value->>'time'=b.value->>'time' and a.pos<b.pos
      and a.value->>'groupId' is distinct from b.value->>'groupId'
    where (a.value->>'completed') is distinct from 'true' and (b.value->>'completed') is distinct from 'true'
      and nullif(a.value->>'date','') is not null and nullif(a.value->>'time','') is not null
  ) then raise exception '이미 예약된 날짜와 시간입니다.' using errcode='23505', constraint='shoeapp_booking_slot_unique'; end if;
  if exists (
    select 1 from public.shoeapp other
    cross join lateral jsonb_array_elements(coalesce(other.payload->'books','[]'::jsonb)) existing(value)
    join lateral jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) candidate(value)
      on candidate.value->>'date'=existing.value->>'date' and candidate.value->>'time'=existing.value->>'time'
    where other.brand is not null and other.brand is distinct from new.brand
      and (existing.value->>'completed') is distinct from 'true' and (candidate.value->>'completed') is distinct from 'true'
  ) then raise exception '이미 다른 브랜드가 예약한 날짜와 시간입니다.' using errcode='23505', constraint='shoeapp_booking_slot_unique'; end if;
  if exists (
    select 1 from jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) b(value)
    join public.shoeapp s on s.brand is not null
    cross join lateral jsonb_array_elements(coalesce(s.payload->'schedules','[]'::jsonb)) e(value)
    cross join lateral jsonb_array_elements_text(coalesce(e.value->'times','[]'::jsonb)) t(value)
    where b.value->>'date'=e.value->>'date' and b.value->>'time'=t.value
      and (b.value->>'completed') is distinct from 'true'
      and nullif(b.value->>'date','') is not null and nullif(b.value->>'time','') is not null
  ) then raise exception '관리자 일정이 등록된 시간에는 미팅을 예약할 수 없습니다.' using errcode='23505', constraint='shoeapp_booking_schedule_unique'; end if;
  if exists (
    select 1 from public.shoeapp s
    cross join lateral jsonb_array_elements(coalesce(s.payload->'schedules','[]'::jsonb)) e(value)
    cross join lateral jsonb_array_elements_text(coalesce(e.value->'times','[]'::jsonb)) t(value)
    cross join lateral jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) b(value)
    where b.value->>'date'=e.value->>'date' and b.value->>'time'=t.value
      and (b.value->>'completed') is distinct from 'true'
  ) then raise exception '예약된 시간이 포함된 관리 일정은 저장할 수 없습니다.' using errcode='23505', constraint='shoeapp_booking_schedule_unique'; end if;
  return new;
end;
$$;
drop trigger if exists shoeapp_booking_slot_guard on public.shoeapp;
create trigger shoeapp_booking_slot_guard before insert or update of payload on public.shoeapp
for each row execute function public.enforce_shoeapp_booking_slot();
notify pgrst, 'reload schema';
