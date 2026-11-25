-- Scope booking time collisions to a brand while preserving shared calendar schedules.
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
      where s.brand is not null and (p_brand is null or s.brand = p_brand)
        and (b.value->>'completed') is distinct from 'true'
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
      where s.brand is not null and e.value->>'date' = p_slot_date::text
        and nullif(t.value #>> '{}','') is not null
    ) slots;
end;
$$;

-- Keep the existing calendar ownership guard and reject duplicate bookings within
-- one brand, but allow separate brands to book the same date and time.
create or replace function public.enforce_shoeapp_booking_slot()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if coalesce(auth.role(),'') <> 'service_role' then
    if tg_op='UPDATE' then
      new.payload := jsonb_set(coalesce(new.payload,'{}'::jsonb), '{schedules}', coalesce(old.payload->'schedules','[]'::jsonb), true);
    else
      new.payload := jsonb_set(coalesce(new.payload,'{}'::jsonb), '{schedules}', '[]'::jsonb, true);
    end if;
  end if;
  perform pg_advisory_xact_lock(hashtextextended('shoeapp_booking_slots',0));
  if exists (
    select 1 from jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) with ordinality a(value,pos)
    join jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) with ordinality b(value,pos)
      on a.value->>'date'=b.value->>'date' and a.value->>'time'=b.value->>'time' and a.pos<b.pos
      and a.value->>'groupId' is distinct from b.value->>'groupId'
    where (a.value->>'completed') is distinct from 'true' and (b.value->>'completed') is distinct from 'true'
      and nullif(a.value->>'date','') is not null and nullif(a.value->>'time','') is not null
  ) then
    raise exception '이미 해당 브랜드에서 예약한 날짜와 시간입니다.'
      using errcode='23505', constraint='shoeapp_booking_slot_unique';
  end if;
  if exists (
    select 1 from jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) b(value)
    join public.shoeapp s on s.brand is not null
    cross join lateral jsonb_array_elements(coalesce(s.payload->'schedules','[]'::jsonb)) e(value)
    cross join lateral jsonb_array_elements_text(coalesce(e.value->'times','[]'::jsonb)) t(value)
    where b.value->>'date'=e.value->>'date' and b.value->>'time'=t.value
      and (b.value->>'completed') is distinct from 'true'
      and nullif(b.value->>'date','') is not null and nullif(b.value->>'time','') is not null
  ) then
    raise exception '관리자 일정이 등록된 시간에는 미팅을 예약할 수 없습니다.'
      using errcode='23505', constraint='shoeapp_booking_schedule_unique';
  end if;
  if exists (
    select 1 from public.shoeapp s
    cross join lateral jsonb_array_elements(coalesce(s.payload->'schedules','[]'::jsonb)) e(value)
    cross join lateral jsonb_array_elements_text(coalesce(e.value->'times','[]'::jsonb)) t(value)
    cross join lateral jsonb_array_elements(coalesce(new.payload->'books','[]'::jsonb)) b(value)
    where b.value->>'date'=e.value->>'date' and b.value->>'time'=t.value
      and (b.value->>'completed') is distinct from 'true'
  ) then
    raise exception '예약된 시간이 포함된 관리 일정은 저장할 수 없습니다.'
      using errcode='23505', constraint='shoeapp_booking_schedule_unique';
  end if;
  return new;
end;
$$;

notify pgrst, 'reload schema';
