#!/usr/bin/env python3
"""NELUUN V9.5 safety prototype patch. Run only on a COPY of V9.4 public/index.html.
Keeps original V9.4 source under version control; NEVER deploy without real-device review.
"""
import argparse
from pathlib import Path
import re

GATE_CSS = r'''
/* V9.5 local guardian gate preview; not native/OS or server-side authorization */
.v95-protect{min-height:75vh;display:grid;place-items:center;padding:24px;background:#0f0e0d;color:#ead4b1}
.v95-card{width:min(100%,520px);padding:28px;border:1px solid #9b7b4b;border-radius:24px;background:#221c16;box-shadow:0 12px 35px #0005}
.v95-card h1{font-family:Georgia,serif;font-size:30px;font-weight:500;margin:0 0 12px}
.v95-card p,.v95-card small{line-height:1.65;color:#d5c4ac}
.v95-card label{display:block;margin:16px 0 8px}
.v95-card input{width:100%;min-height:48px;border-radius:12px;border:1px solid #8b744b;background:#100e0c;color:#fff;padding:12px}
.v95-card button{margin:16px 10px 4px 0;padding:12px 18px;border:1px solid #b89968;border-radius:12px;color:#21180f;background:#ebc891}
.v95-card button.v95-secondary{background:transparent;color:#ead4b1}
.v95-error{border:1px solid #d17d7d;background:#491b1b;color:white;border-radius:12px;padding:12px;margin:12px 0}
'''

GATE_JS = r'''
// V9.5 DEVELOPMENT PREVIEW: local adult data encrypted at rest with Web Crypto.
// This does not protect logged-in server APIs, account deletion, OS-level secrets, or all browser bypasses.
const V95_VAULT='neluun_v95_adult_vault',V95_FAIL='neluun_v95_failed_unlock';
let v95Key=null,v95WriteQueue=Promise.resolve(),v95Error='';
s.v95Unlocked=false;
const v95HasVault=()=>{try{return !!localStorage.getItem(V95_VAULT)}catch{return false}};
const v95BytesTo64=bytes=>btoa(Array.from(bytes,b=>String.fromCharCode(b)).join(''));
const v95BytesFrom64=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));
const v95Rand=n=>crypto.getRandomValues(new Uint8Array(n));
async function v95Derive(password,salt){
 const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations:310000},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function v95Envelope(payload,key,salt){
 const iv=v95Rand(12),plaintext=new TextEncoder().encode(JSON.stringify(payload));
 const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,plaintext);
 return JSON.stringify({v:1,kdf:'PBKDF2-SHA256',iterations:310000,salt:v95BytesTo64(salt),iv:v95BytesTo64(iv),data:v95BytesTo64(new Uint8Array(ciphertext))});
}
async function v95Open(envelope,key){
 const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:v95BytesFrom64(envelope.iv)},key,v95BytesFrom64(envelope.data));
 const value=JSON.parse(new TextDecoder().decode(raw));
 if(!value||!Array.isArray(value.tasks)||!Array.isArray(value.notes))throw Error('加密資料格式錯誤');
 return {tasks:value.tasks.slice(0,80).filter(x=>x&&typeof x.text==='string').map(x=>({text:x.text.slice(0,80),done:!!x.done})),notes:value.notes.filter(x=>typeof x==='string').slice(0,80).map(x=>x.slice(0,300))};
}
function v95ChildSnapshot(){return {grade:s.grade,completed:s.completed,attempts:s.attempts,history:(s.history||[]).slice(0,60)}}
async function v95PersistAdult(tasks,notes,key=v95Key){
 if(!key)throw Error('家長尚未解鎖');
 const prev=JSON.parse(localStorage.getItem(V95_VAULT));
 const packed=await v95Envelope({tasks,notes},key,v95BytesFrom64(prev.salt));
 localStorage.setItem(V95_VAULT,packed);
}
function v95QueueSave(){
 if(!s.v95Unlocked||!v95Key||!v95HasVault())return;
 const tasks=s.tasks.map(t=>({...t})),notes=s.notes.slice(),key=v95Key;
 v95WriteQueue=v95WriteQueue.then(()=>v95PersistAdult(tasks,notes,key));
 v95WriteQueue.catch(e=>{v95Error='儲存失敗：請勿關閉 App，先匯出備份。';console.error('V9.5 secure write failed',e)});
}
function v95Lock(){
 if(s.v95Unlocked)v95QueueSave();
 s.v95Unlocked=false;v95Key=null;
 // Before first lock enrollment retain legacy data in memory for lossless migration.
 // Locked screens never render that data; after enrollment only ciphertext is stored.
 if(v95HasVault()){s.tasks=[];s.notes=[];}
 s.adultMessages=[];s.adultConversations=[];s.adultAiConsent=false;
}
function v95Gate(){
 const setup=!v95HasVault();
 const blocked=(()=>{try{return JSON.parse(localStorage.getItem(V95_FAIL)||'{}').until>Date.now()}catch{return false}})();
 return `<div class="v95-protect"><section class="v95-card"><h1>🔐 ${setup?'設定家長安全鎖':'家長解鎖'}</h1><p>${setup?'首次進入成人私人區，請先以電子郵件驗證登入，再設定此裝置的家長密碼。會員登入和家長鎖是兩個不同步驟。':'進入成人私人空間前，需要家長密碼。即使已登入會員，也必須先解鎖。'}</p><p>兒童免費本機練習不需要登入。家長安全鎖保護本機私人資料，但尚未完成原生裝置驗證或伺服器權限驗證。</p>${v95Error?`<div class="v95-error" role="alert">${html(v95Error)}</div>`:''}${setup&&!s.auth.authenticated?accountArea():''}<form data-form="${setup?'v95Enroll':'v95Unlock'}"><label for="v95pw">家長密碼</label><input id="v95pw" name="password" type="password" autocomplete="off" minlength="8" maxlength="64" required ${blocked?'disabled':''}>${setup?'<label for="v95confirm">再輸入一次密碼</label><input id="v95confirm" name="confirmation" type="password" autocomplete="off" minlength="8" maxlength="64" required>':''}<button type="submit" ${blocked?'disabled':''}>${setup?'啟用家長安全鎖':'解鎖成人區'}</button><button type="button" class="v95-secondary" data-action="choose">返回雙入口</button></form>${setup?'<small>建議使用至少 8 字元且同時包含英文和數字的獨立密碼。設定後會加密此裝置原有待辦和筆記，不會修改雲端登入資料。忘記密碼無法直接復原，請安全保存備份。</small>':'<small>連續輸入錯誤 5 次會暫停 1 分鐘。這不是完整的防破解措施；正式 App 仍需原生安全儲存與 API 權限驗證。</small>'}</section></div>`;
}
async function v95Enroll(form){
 try{
  if(v95HasVault())throw Error('已存在安全鎖，請改用解鎖');
  if(!s.authOnline||!s.auth.authenticated)throw Error('請先完成成人電子郵件驗證登入，才能設定家長安全鎖');
  if(!globalThis.isSecureContext||!crypto?.subtle)throw Error('需要安全 HTTPS 網頁或原生安全來源');
  const f=new FormData(form),password=String(f.get('password')||''),confirmation=String(f.get('confirmation')||'');
  if(password!==confirmation)throw Error('兩次輸入的家長密碼不同');
  if(!/^(?=.*[A-Za-z])(?=.*[0-9]).{8,64}$/.test(password))throw Error('請使用 8～64 字元、含英文和數字的家長密碼');
  const salt=v95Rand(16),key=await v95Derive(password,salt);
  const originalTasks=s.tasks.map(t=>({...t})),originalNotes=s.notes.slice();
  const envelope=await v95Envelope({tasks:originalTasks,notes:originalNotes},key,salt);
  // Write the sealed vault first. If any step fails, old plaintext is preserved to avoid data loss.
  localStorage.setItem(V95_VAULT,envelope);
  try{localStorage.setItem(STORE,JSON.stringify(v95ChildSnapshot()))}catch(e){
   localStorage.removeItem(V95_VAULT);throw Error('無法安全遷移原本資料；尚未覆蓋原資料');
  }
  v95Key=key;s.v95Unlocked=true;v95Error='';render();
 }catch(e){v95Error=e.message||'安全鎖設定失敗';render()}
}
async function v95Unlock(form){
 try{
  const rate=JSON.parse(localStorage.getItem(V95_FAIL)||'{}');
  if(rate.until>Date.now())throw Error('密碼錯誤次數過多，請稍後再試');
  if(!globalThis.isSecureContext||!crypto?.subtle)throw Error('此環境不支援安全加密');
  const password=String(new FormData(form).get('password')||'');
  const vault=JSON.parse(localStorage.getItem(V95_VAULT)||'null');
  if(!vault||vault.v!==1||vault.kdf!=='PBKDF2-SHA256'||vault.iterations!==310000)throw Error('此裝置的家長鎖資料無效');
  const key=await v95Derive(password,v95BytesFrom64(vault.salt));
  let restored;
  try{restored=await v95Open(vault,key)}catch{
   const count=(Number(rate.count)||0)+1;
   localStorage.setItem(V95_FAIL,JSON.stringify({count:count>=5?0:count,until:count>=5?Date.now()+60000:0}));
   throw Error(count>=5?'已暫停解鎖 1 分鐘':'家長密碼錯誤');
  }
  localStorage.removeItem(V95_FAIL);
  v95Key=key;Object.assign(s,restored);s.v95Unlocked=true;v95Error='';render();
 }catch(e){v95Error=e.message||'解鎖失敗';render()}
}
document.addEventListener('visibilitychange',()=>{if(document.hidden){v95Lock();render()}});
'''

def replace_once(src,old,new,label):
    n=src.count(old)
    if n!=1:raise ValueError(f'Anchor {label}: expected once, got {n}. SOURCE UNCHANGED.')
    return src.replace(old,new,1)

def patch(source):
    if 'NELUUN_V95_GUARD' in source:raise ValueError('V9.5 patch already applied')
    if 'V9.4 · SAFE CONNECTION' not in source:raise ValueError('Expected V9.4 baseline not found')
    output=source
    output=replace_once(output,'</style>','\n'+GATE_CSS+'\n</style>','style')
    output=replace_once(output,"const STORE='neluun_v8_local'; // Retain V8 local data; do not overwrite backups", "const STORE='neluun_v8_local'; // Retain V8 local data; do not overwrite backups\n// NELUUN_V95_GUARD: separate adult encrypted vault with required parent unlock.\n"+GATE_JS,'storage/gate injection')
    output=replace_once(output,
      "function saveLocal(){try{localStorage.setItem(STORE,JSON.stringify({tasks:s.tasks.slice(-80),notes:s.notes.slice(-80),grade:s.grade,completed:s.completed,attempts:s.attempts,history:(s.history||[]).slice(0,60)}))}catch(err){console.warn('無法儲存本機紀錄',err)}}",
      """function saveLocal(){try{
 const d=v95ChildSnapshot();
 if(!v95HasVault()){
  // Preserve V8/V9 plaintext data until successful parent lock enrollment.
  const previous=JSON.parse(localStorage.getItem(STORE)||'{}');
  d.tasks=Array.isArray(previous.tasks)?previous.tasks:s.tasks.slice(-80);
  d.notes=Array.isArray(previous.notes)?previous.notes:s.notes.slice(-80);
 }
 localStorage.setItem(STORE,JSON.stringify(d));v95QueueSave();
 }catch(err){console.warn('無法儲存本機紀錄',err);v95Error='本機儲存失敗，請先確認備份'}}""",'saveLocal')
    output=replace_once(output,"function downloadLocal(){", "function downloadLocal(){if(!s.v95Unlocked){alert('請先通過家長安全鎖，才能匯出成人資料');return;}", 'export guard')
    output=replace_once(output,
      "  const value=JSON.stringify(restored);\n  try{localStorage.setItem(STORE,value)}catch{throw Error('無法寫入本機儲存空間；原本資料未被覆蓋。')}\n  Object.assign(s,restored);",
      """   if(!s.v95Unlocked||!v95HasVault())throw Error('請先設定並解鎖家長安全鎖');
   await v95WriteQueue;
   await v95PersistAdult(restored.tasks,restored.notes);
   try{localStorage.setItem(STORE,JSON.stringify({grade:restored.grade,completed:restored.completed,attempts:restored.attempts,history:restored.history}))}catch{throw Error('學習資料寫入失敗；請再次核對資料')}
   Object.assign(s,restored);""",'import secure')
    output=replace_once(output,"function clearLocal(){if(!confirm(","function clearLocal(){if(!s.v95Unlocked){alert('請先解鎖家長區');return;}if(!confirm(",'clear guard')
    output=replace_once(output,"try{localStorage.removeItem(STORE)}catch{};s.tasks=[]", "try{localStorage.removeItem(STORE);localStorage.removeItem(V95_VAULT);localStorage.removeItem(V95_FAIL)}catch{};v95Key=null;s.v95Unlocked=false;s.tasks=[]",'clear vault')
    # Only display account login inside the unlocked adult settings / parent zone.
    pattern=r'<button class="choice-account-btn" type="button" data-action="homeAccount" aria-label="\$\{s\.auth\.authenticated\?.*?</button>'
    output,n=re.subn(pattern,'',output,count=1)
    if n!=1:raise ValueError('Cannot remove global login button; abort')
    output=replace_once(output,'V9.4 · SAFE CONNECTION','V9.5 · FAMILY SAFETY PREVIEW','version title')
    output=replace_once(output,
      "function render(){saveLocal();app.innerHTML=s.mode==='choice'?choose():s.mode==='adult'?renderAdult():renderChild();document.body.style.backgroundColor=s.mode==='adult'?'#0f0e0d':s.mode==='child'?'#fce8ef':'#eee9e4'}",
      """function render(){saveLocal();app.innerHTML=(s.mode==='adult'&&!s.v95Unlocked)||(s.mode==='child'&&s.childView==='parent'&&!s.v95Unlocked)?v95Gate():s.mode==='choice'?choose():s.mode==='adult'?renderAdult():renderChild();document.body.style.backgroundColor=s.mode==='adult'?'#0f0e0d':s.mode==='child'?'#fce8ef':'#eee9e4'}""",'render gate')
    output=replace_once(output,
      "function view(target){if(s.mode==='adult'){s.adultView=target==='you'?'you':target}else if(s.mode==='child'){s.childView=target}render();window.scrollTo(0,0)}",
      """function view(target){if(s.mode==='adult'){s.adultView=target==='you'?'you':target}else if(s.mode==='child'){if(s.childView==='parent'&&target!=='parent')v95Lock();s.childView=target}render();window.scrollTo(0,0)}""",'view')
    output=replace_once(output," case 'exportLocal':downloadLocal();break;", " case 'exportLocal':downloadLocal();break;", 'export (no-op validation)')
    output=replace_once(output," case 'mode':s.mode=button.dataset.mode;render();window.scrollTo(0,0);break;",
       "  case 'mode':v95Lock();s.mode=button.dataset.mode;render();window.scrollTo(0,0);break;",'mode')
    output=replace_once(output," case 'choose':s.mode='choice';s.homeAccountOpen=false;render();window.scrollTo(0,0);break;",
       "  case 'choose':v95Lock();s.mode='choice';s.homeAccountOpen=false;render();window.scrollTo(0,0);break;",'choose')
    output=replace_once(output,
      "if(kind==='requestLogin'){", "if(kind==='v95Enroll'){v95Enroll(form);return;}if(kind==='v95Unlock'){v95Unlock(form);return;}if(kind==='requestLogin'){",'form action')
    output=replace_once(output,
      "  if(el.dataset.action==='importLocalFile'){", "   if(el.dataset.action==='importLocalFile'&&!s.v95Unlocked){alert('請先通過家長安全鎖');return;}\n   if(el.dataset.action==='importLocalFile'){",'import event')
    output=replace_once(output,
      " case 'homeAccount':s.homeAccountOpen=true;render();break;",
      "  case 'homeAccount':if(!s.v95Unlocked){s.mode='adult';render();break;}s.homeAccountOpen=true;render();break;",'home account')
    # Ensure these are still present.
    for key in ["case 'subject'","function childSubjects()","function adultTools()","function refreshAuth", "v95Envelope", "V9.5 · FAMILY SAFETY PREVIEW"]:
       if key not in output:raise ValueError('Missing essential function '+key)
    return output

def main():
    parser=argparse.ArgumentParser();parser.add_argument('source',type=Path);parser.add_argument('--output',type=Path);args=parser.parse_args()
    original=args.source.read_text('utf-8')
    result=patch(original)
    dest=args.output or args.source
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(result,encoding='utf-8')
    print(f'NELUUN V9.5 preview generated: {dest}, bytes={len(result.encode("utf-8"))}')

if __name__=='__main__':main()
