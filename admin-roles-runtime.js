  const style=document.createElement('style');
  style.textContent='.manager-modal{width:min(900px,100%);max-height:90vh;overflow:auto}.manager-modal>p{font-size:12px;color:#687168;line-height:1.6}.manager-cards{display:grid;grid-template-columns:1fr 1fr;gap:12px}.manager-card{border:1px solid var(--line);border-radius:10px;padding:14px}.manager-card-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.manager-card-head small,.manager-count{margin-left:auto;color:var(--muted);font-size:11px}.manager-brand-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin:13px 0}.manager-brand-option{display:flex;align-items:center;gap:5px;font-size:11px}.manager-password-label{display:grid;gap:6px;font-size:11px;color:var(--muted)}.manager-password-label input{border:1px solid var(--line);border-radius:7px;padding:9px}.manager-card-head label{font-size:11px}.manager-modal .feed-row{align-items:center}.manager-modal .feed-row p{flex:1}@media(max-width:700px){.manager-cards{grid-template-columns:1fr}}';
  document.head.appendChild(style);
async function readRemoteState(){
  if(current?.role==='관리자'&&adminToken){
    const result=await adminApi('read');
    if(!['super_admin','manager'].includes(result.role))throw new Error('관리자 권한을 확인하지 못했습니다. 다시 로그인해 주세요.');
    const role=result.role;
    current.adminRole=role;current.managerSlot=result.managerSlot??null;current.brand='전체';
    current.name=role==='super_admin'?'최종 관리자':`브랜드관리자 ${result.managerSlot}`;
    managerBrands=result.brands||[];filterBrand='전체';
    samples=result.rows.flatMap(row=>Array.isArray(row.payload?.samples)?row.payload.samples:[]);
    books=result.rows.flatMap(row=>Array.isArray(row.payload?.books)?row.payload.books:[]);
    season=result.rows.find(row=>row.payload?.season)?.payload.season||'';schedules=result.schedules||[];sharedCalendarBookings=result.calendarBookings||[];return;
  }
  const userId=supaSession?.user?.id;if(!userId)throw new Error('로그인이 필요합니다.');
  const memberResponse=await supabaseFetch('rest/v1/shoeapp_memberships?select=brand,username&user_id=eq.'+encodeURIComponent(userId),{cache:'no-store'});
  if(!memberResponse.ok)throw new Error('브랜드 권한을 확인할 수 없습니다. 최신 Supabase 설정 SQL을 실행했는지 확인해 주세요.');
  const members=await memberResponse.json();if(!members.length)throw new Error('브랜드 권한이 등록되지 않았습니다. 다시 회원가입하거나 관리자에게 확인해 주세요.');
  current={name:members[0].username||supaSession.user.user_metadata?.username||'사용자',email:supaSession.user.email||'',brand:members[0].brand,role:'브랜드 담당자'};filterBrand=current.brand;
  const [response,scheduleResponse]=await Promise.all([
    supabaseFetch('rest/v1/shoeapp?select=brand,payload&brand=eq.'+encodeURIComponent(current.brand),{cache:'no-store'}),
    supabaseFetch('rest/v1/shoeapp_admin_schedules?select=id,schedule_date,title,times,brand&order=schedule_date.asc',{cache:'no-store'})
  ]);
  if(!response.ok)throw new Error('선택한 브랜드 데이터를 읽을 수 없습니다. Supabase RLS 정책을 확인해 주세요.');
  if(!scheduleResponse.ok)throw new Error('공유 달력 일정을 읽을 수 없습니다. 최신 Supabase 설정을 실행했는지 확인해 주세요.');
  const rows=await response.json(),state=rows.length?rows[0].payload:{samples:[],books:[],season:''};
  samples=Array.isArray(state.samples)?state.samples:[];books=Array.isArray(state.books)?state.books:[];
  schedules=(await scheduleResponse.json()).map(row=>({id:row.id,date:row.schedule_date,title:row.title,times:row.times,brand:row.brand}));season=state.season||'';
}

async function fetchReservedTimes(date,brand){
  if(!date)return new Set();
  if(isMiddleAdmin()){const result=await adminApi('reserved_slots',{date,brand});return new Set(result.times||[])}
  if(isFinalAdmin())return new Set([
    ...books.filter(b=>!b.completed&&b.date===date&&b.brand===brand).map(b=>String(b.time||'')),
    ...schedules.filter(x=>x.date===date&&(x.brand==null||x.brand===brand)).flatMap(x=>x.times||[])
  ]);
  const response=await supabaseFetch('rest/v1/rpc/shoeapp_reserved_slots',{method:'POST',cache:'no-store',body:JSON.stringify({p_slot_date:date,p_brand:brand||current?.brand})});
  if(!response.ok){const result=await response.json().catch(()=>({}));throw new Error(result.message||'전 브랜드 예약 시간을 불러오지 못했습니다.')}
  return new Set((await response.json()).map(row=>String(row.slot_time||'')));
}

function openScheduleViewer(date){
  const day=schedules.filter(x=>x.date===date);
  const rows=day.length?day.map(x=>`<article class="feed-row"><span class="feed-dot"></span><p><strong>${h(x.title)}</strong><small>${h(x.brand||'공통 일정')} · ${h((x.times||[]).join(', ')||'시간 미정')}</small></p></article>`).join(''):'<p style="color:#7d817b">등록된 관리자 일정이 없습니다.</p>';
  document.getElementById('modal').innerHTML=`<div class="modal"><div class="modal-top"><h2>${h(date)} 관리자 일정</h2><button class="close" onclick="closeModal()">×</button></div><div>${rows}</div><div class="modal-actions"><button type="button" class="btn" onclick="closeModal()">닫기</button></div></div>`;
  document.getElementById('modal').classList.add('show');
}

function selectCalendarDay(date){if(current?.role==='관리자')openScheduleDay(date);else openScheduleViewer(date)}
function openScheduleDay(date){
  const day=schedules.filter(x=>x.date===date);
  const dayMeetings=(isMiddleAdmin()?sharedCalendarBookings:books).filter(item=>item.date===date&&!item.completed);
  const bookingRows=dayMeetings.map(item=>`<article class="feed-row"><span class="feed-dot"></span><p><strong>${h(item.brand)} · ${h(item.sample||'미팅')}</strong><small>미팅 예약 · ${h(item.time||'시간 미정')}${item.room?' · '+h(item.room):''}</small></p></article>`).join('');
  const scheduleRows=day.length?day.map(item=>{
    const editable=isFinalAdmin()||(isMiddleAdmin()&&item.brand!==null&&managerBrands.includes(item.brand));
    return `<article class="feed-row"><span class="feed-dot"></span><p><strong>${h(item.title)}</strong><small>${h(item.brand||'공통 일정')} · ${h((item.times||[]).join(', '))}</small></p>${editable?`<button class="btn light small" type="button" onclick="openScheduleForm('${h(date)}','${h(item.id)}')">수정</button>`:''}</article>`;
  }).join(''):'';
  const rows=bookingRows+scheduleRows||'<p style="color:#7d817b">등록된 일정이 없습니다.</p>';
  const add=(isFinalAdmin()||isMiddleAdmin())?`<button type="button" class="btn" onclick="openScheduleForm('${h(date)}')">＋ 일정 등록</button>`:'';
  document.getElementById('modal').innerHTML=`<div class="modal"><div class="modal-top"><h2>${h(date)} 일정</h2><button class="close" onclick="closeModal()">×</button></div><div>${rows}</div><div class="modal-actions">${add}<button type="button" class="btn light" onclick="closeModal()">닫기</button></div></div>`;
  document.getElementById('modal').classList.add('show');
}

function openScheduleForm(date,id=''){
  if(!isFinalAdmin()&&!isMiddleAdmin()){toast('관리자만 일정을 관리할 수 있습니다.');return}
  const old=schedules.find(x=>x.id===id);
  if(old&&!isFinalAdmin()&&(old.brand===null||!managerBrands.includes(old.brand))){toast('배정된 브랜드 일정만 수정할 수 있습니다.');return}
  const options=isFinalAdmin()?[['','공통 일정'],...BRANDS.map(brand=>[brand,brand])]:managerBrands.map(brand=>[brand,brand]);
  const defaultBrand=old?old.brand:(isFinalAdmin()?(filterBrand!=='전체'?filterBrand:''):(managerBrands.includes(filterBrand)?filterBrand:managerBrands[0]||''));
  const times=Array.from({length:23},(_,n)=>{const i=n+15;return String(Math.floor(i/2)).padStart(2,'0')+':'+(i%2?'30':'00')});
  document.getElementById('modal').innerHTML=`<div class="modal"><div class="modal-top"><h2>${old?'관리 일정 변경':date+' 일정 등록'}</h2><button class="close" onclick="closeModal()">×</button></div><form onsubmit="saveSchedule(event,'${h(date)}','${h(old?.id||'')}')"><div class="formrow"><label>일정명</label><input name="title" maxlength="80" required value="${h(old?.title||'')}"></div><div class="formrow" style="margin-top:12px"><label>브랜드 범위</label><select name="scheduleBrand" required>${options.map(([value,label])=>`<option value="${h(value)}" ${value===defaultBrand?'selected':''}>${h(label)}</option>`).join('')}</select></div><div class="formrow" style="margin-top:12px"><label>시간대 복수 선택</label><div class="schedule-time-actions"><button type="button" class="btn light small" onclick="setScheduleTimeSelection(true)">전체 선택</button><button type="button" class="btn light small" onclick="setScheduleTimeSelection(false)">전체 취소</button></div><div class="time-choices">${times.map(time=>`<label><input type="checkbox" name="scheduleTimes" value="${time}" ${old?.times?.includes(time)?'checked':''}>${time}</label>`).join('')}</div></div><div class="modal-actions">${old?`<button type="button" class="btn light danger" onclick="deleteSchedule('${h(old.id)}')">일정 삭제</button>`:''}<button type="button" class="btn light" onclick="closeModal()">취소</button><button class="btn">저장</button></div></form></div>`;
  document.getElementById('modal').classList.add('show');
}
async function saveSchedule(event,date,id){
  event.preventDefault();const form=event.target,formData=new FormData(form),title=String(formData.get('title')||'').trim(),times=[...form.querySelectorAll('[name="scheduleTimes"]:checked')].map(item=>item.value).sort(),brand=String(formData.get('scheduleBrand')||'')||null;
  if(!title||!times.length){toast('일정명과 시간을 선택해 주세요.');return}
  if(!isFinalAdmin()&&(!brand||!managerBrands.includes(brand))){toast('배정된 브랜드만 일정을 등록할 수 있습니다.');return}
  try{await adminApi('schedule_save',{schedule:{id:id||undefined,date,title,times,brand}});await readRemoteState();closeModal();render();toast('관리 일정이 저장되었습니다.')}
  catch(error){toast(error.message||'일정을 저장하지 못했습니다.')}
}
async function deleteSchedule(id){
  const item=schedules.find(x=>x.id===id);
  if(!item||(!isFinalAdmin()&&(item.brand===null||!managerBrands.includes(item.brand)))||!confirm('관리 일정을 삭제할까요?'))return;
  try{await adminApi('schedule_delete',{id});await readRemoteState();closeModal();render();toast('관리 일정이 삭제되었습니다.')}
  catch(error){toast(error.message||'일정을 삭제하지 못했습니다.')}
}

async function refreshBookingTimes(){
  const requestId=++bookingTimeRequestId,date=document.querySelector('#modal input[name="date"]')?.value,brand=document.querySelector('#modal select[name="brand"]')?.value||(isMiddleAdmin()?managerBrands[0]:current?.brand),host=document.getElementById('bookingTimes'),status=document.getElementById('bookingTimeStatus');
  if(!host)return;const inputs=[...host.querySelectorAll('input[name="time"]')],selected=inputs.filter(input=>input.checked).map(input=>input.value);
  if(!date){inputs.forEach(input=>{input.disabled=false;input.nextElementSibling.textContent=input.value});if(status)status.textContent='날짜를 선택하면 예약된 시간이 표시됩니다.';return}
  if(status)status.textContent='예약 가능 시간을 확인하고 있습니다.';inputs.forEach(input=>input.disabled=true);
  try{const reserved=await fetchReservedTimes(date,brand);if(requestId!==bookingTimeRequestId)return;const edit=editingBookingIndex>=0?books[editingBookingIndex]:null,ownTimes=new Set(edit?.groupId?books.filter(item=>item.groupId===edit.groupId&&item.date===date).map(item=>item.time):edit?.date===date?[edit.time]:[]);inputs.forEach(input=>{const blocked=reserved.has(input.value)&&!ownTimes.has(input.value);input.disabled=blocked;input.nextElementSibling.textContent=input.value+(blocked?' (예약됨)':'');if(blocked)input.checked=false});if(status)status.textContent='예약된 시간은 회색으로 표시되며 선택할 수 없습니다.';if(selected.some(time=>reserved.has(time)&&!ownTimes.has(time)))toast('이미 예약된 시간은 선택할 수 없습니다.')}
  catch(error){if(requestId!==bookingTimeRequestId)return;inputs.forEach(input=>{input.disabled=true;input.nextElementSibling.textContent=input.value+' (조회 실패)'});if(status)status.textContent='예약 가능 시간을 불러오지 못했습니다.';toast(error.message||'예약 가능 시간을 불러오지 못했습니다.')}
}

function openManagerAccessDialog(){
  if(!isFinalAdmin()){toast('최종 관리자만 브랜드관리자 권한을 관리할 수 있습니다.');return}
  adminApi('managers_read').then(({managers,brands})=>{
    const assigned=new Map();for(const manager of managers)for(const brand of manager.brands)assigned.set(brand,manager.managerSlot);
    const cards=managers.map(manager=>`<section class="manager-card" data-must-change-password="${manager.mustChangePassword?'true':'false'}"><div class="manager-card-head"><strong>브랜드관리자 ${manager.managerSlot}</strong><label><input type="checkbox" name="managerActive" value="${manager.managerSlot}" ${manager.active?'checked':''}> 활성화</label><small>${manager.mustChangePassword?'임시 비밀번호 · 새 비밀번호 필요':manager.hasPassword?'비밀번호 설정됨':'비밀번호 미설정'}</small></div><div class="manager-brand-grid">${brands.map(brand=>{const owner=assigned.get(brand),checked=manager.brands.includes(brand);return `<label class="manager-brand-option"><input type="checkbox" name="managerBrand${manager.managerSlot}" value="${h(brand)}" ${checked?'checked':''}>${h(brand)}${owner&&owner!==manager.managerSlot?' · 현재 브랜드관리자 '+owner:''}</label>`}).join('')}</div><label class="manager-password-label">새 비밀번호<input type="password" name="managerPassword${manager.managerSlot}" minlength="12" maxlength="128" autocomplete="new-password" placeholder="${manager.hasPassword?'변경할 때만 입력':'12자 이상 입력'}"></label><small class="manager-count" id="managerCount${manager.managerSlot}">${manager.brands.length}/3 브랜드</small></section>`).join('');
    document.getElementById('modal').innerHTML=`<div class="modal manager-modal"><div class="modal-top"><h2>브랜드관리자 권한 관리</h2><button class="close" onclick="closeModal()">×</button></div><p>브랜드는 중복 배정할 수 없습니다. 활성 계정은 고유 브랜드 2~3개와 비밀번호가 필요합니다. 배정을 저장하면 브랜드관리자 세션이 종료됩니다.</p><form onsubmit="saveManagerAccess(event)"><div class="manager-cards">${cards}</div><div class="modal-actions"><button type="button" class="btn light" onclick="closeModal()">취소</button><button class="btn">권한 저장</button></div></form></div>`;
    document.getElementById('modal').classList.add('show');
    document.querySelectorAll('[name^="managerBrand"]').forEach(input=>input.addEventListener('change',()=>{const slot=input.name.replace('managerBrand',''),count=document.querySelectorAll('[name="managerBrand'+slot+'"]:checked').length;document.getElementById('managerCount'+slot).textContent=count+'/3 브랜드'}));
  }).catch(error=>toast(error.message||'관리자 권한을 불러오지 못했습니다.'));
}
async function saveManagerAccess(event){
  event.preventDefault();if(!isFinalAdmin()){toast('최종 관리자만 권한을 변경할 수 있습니다.');return}
  const form=event.target,managers=[1,2,3,4].map(managerSlot=>({managerSlot,active:form.querySelector('[name="managerActive"][value="'+managerSlot+'"]')?.checked===true,brands:[...form.querySelectorAll('[name="managerBrand'+managerSlot+'"]:checked')].map(input=>input.value),password:form.querySelector('[name="managerPassword'+managerSlot+'"]')?.value||''}));
  for(const manager of managers){const card=document.querySelector('[name=managerActive][value="'+manager.managerSlot+'"]')?.closest('.manager-card');if(manager.brands.length>3||manager.active&&(manager.brands.length<2||manager.brands.length>3)){toast('활성 브랜드관리자는 브랜드를 2~3개 선택해 주세요.');return}if(manager.active&&!manager.password&&card?.dataset.mustChangePassword==='true'){toast('브랜드관리자 '+manager.managerSlot+'의 임시 비밀번호를 12자 이상의 새 비밀번호로 변경해 주세요.');return}if(manager.password&&manager.password.length<12){toast('새 비밀번호는 12자 이상으로 입력해 주세요.');return}}
  try{await adminApi('managers_save',{managers});toast('브랜드관리자 권한을 저장했습니다. 기존 브랜드관리자 세션은 종료되었습니다.');openManagerAccessDialog()}
  catch(error){toast(error.message||'브랜드관리자 권한을 저장하지 못했습니다.')}
}

// Enforce final-administrator-only reset from the handler as well as the hidden button.
const existingResetDialog=openResetDialog;
openResetDialog=function(){if(!isFinalAdmin()){toast('최종 관리자만 전체 리셋을 실행할 수 있습니다.');return}existingResetDialog()};
const existingConfirmReset=confirmReset;
confirmReset=async function(event){if(!isFinalAdmin()){toast('최종 관리자만 전체 리셋을 실행할 수 있습니다.');return}return existingConfirmReset(event)};

const baseRenderAuth=renderAuth;
renderAuth=function(mode='signup'){
  const brandAdmin=mode==='brand-admin';baseRenderAuth(brandAdmin?'admin':mode);
  const box=document.querySelector('.auth-box');if(!box)return;
  const tabs=box.querySelector('.auth-tabs');
  if(brandAdmin)tabs.querySelectorAll('.auth-tab.active').forEach(tab=>tab.classList.remove('active'));
  const button=document.createElement('button');button.type='button';button.className='auth-tab'+(brandAdmin?' active':'');button.textContent='브랜드관리자 로그인';button.onclick=()=>renderAuth('brand-admin');tabs.appendChild(button);
  tabs.classList.add('auth-tabs-manager');
  if(brandAdmin){box.querySelector('h2').textContent='브랜드관리자 로그인';box.querySelector('p').textContent='최종 관리자에게 부여받은 브랜드관리자 비밀번호를 입력하세요.';const form=box.querySelector('.auth-form');form.setAttribute('onsubmit',"authSubmit(event,'brand-admin')");form.innerHTML='<div class="formrow"><label>브랜드관리자 비밀번호</label><input type="password" name="password" autocomplete="current-password" required placeholder="부여받은 비밀번호"></div><button class="btn" style="margin-top:5px">브랜드관리자 로그인</button>';box.querySelector('.demo').textContent='브랜드 범위는 최종 관리자가 설정한 권한에 따라 적용됩니다.'}
};
const baseAuthSubmit=authSubmit;
authSubmit=function(event,mode){return baseAuthSubmit(event,mode==='brand-admin'?'admin':mode)};
  const baseRender=render;
  render=function(){baseRender();if(!isFinalAdmin())return;document.querySelectorAll('button').forEach(button=>{if(button.textContent.trim()==='브랜드관리자 권한')button.remove()});const syncButton=document.getElementById('syncButton');if(!syncButton)return;const accessButton=document.createElement('button');accessButton.type='button';accessButton.className='btn light small';accessButton.textContent='⚙ 관리자 권한 관리';accessButton.onclick=openManagerAccessDialog;syncButton.after(accessButton)};
