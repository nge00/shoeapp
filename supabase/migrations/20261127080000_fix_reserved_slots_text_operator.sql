-- Fix the reserved-slot RPC for text values returned by jsonb_array_elements_text.
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
      select t.value as slot_time
      from public.shoeapp s
      cross join lateral jsonb_array_elements(coalesce(s.payload->'schedules','[]'::jsonb)) e(value)
      cross join lateral jsonb_array_elements_text(coalesce(e.value->'times','[]'::jsonb)) t(value)
      where s.brand is not null and e.value->>'date' = p_slot_date::text
        and nullif(t.value,'') is not null
    ) slots;
end;
$$;
revoke all on function public.shoeapp_reserved_slots(date, text) from public, anon;
grant execute on function public.shoeapp_reserved_slots(date, text) to authenticated;
notify pgrst, 'reload schema';
