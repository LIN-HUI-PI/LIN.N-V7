/**
 * NELUUN V9.5 parent step-up browser client — staging only.
 * The server must authorize each sensitive API; this helper does not itself
 * grant legal-guardian status or unlock adult records.
 * Never store OTP, access flags, or session tokens in localStorage.
 */
export class ParentStepUpClient {
  constructor({request = (...args) => fetch(...args)} = {}) {
    this.request = request;
    this.unlocked = false; // ephemeral UI hint, NEVER a server permission
  }
  async call(path, method='GET', payload) {
    if(!/^\/api\/parent\/(status|challenge|verify|lock)$/.test(path))
      throw Error('Unsupported parent API route');
    const options={method,credentials:'same-origin',cache:'no-store',
      headers:{accept:'application/json'}};
    if(method!=='GET'){
      options.headers['content-type']='application/json';
      options.body=JSON.stringify(payload||{});
    }
    let response;
    try { response=await this.request(path,options); }
    catch {
      this.unlocked=false;
      throw Error('驗證伺服器暫時無法連線，成人區保持鎖定。');
    }
    let body;
    try{body=await response.json()}catch{
      this.unlocked=false;
      throw Error('安全驗證回應異常，成人區保持鎖定。');
    }
    if(!response.ok||body?.ok!==true){
      this.unlocked=false;
      const known={
        sign_in:'請先完成成人會員登入。',
        invalid_code:'驗證碼錯誤或已過期。',
        adult_locked:'成人區尚未驗證。',
        try_later:'嘗試過於頻繁，請稍後再試。',
        cooldown:'請稍後再要求驗證碼。',
        not_configured:'家長二次驗證尚未啟用。'
      };
      const e=new Error(known[body?.error]||body?.message||'安全驗證未通過。');
      e.code=String(body?.error||'unknown');e.status=response.status;
      throw e;
    }
    return body;
  }
  async status(){
    const data=await this.call('/api/parent/status');
    this.unlocked=data.adultAccess===true && Number(data.expiresIn)>0;
    return this.unlocked;
  }
  async challenge(){
    this.unlocked=false;
    return this.call('/api/parent/challenge','POST',{});
  }
  async verify(code){
    if(typeof code!=='string'||!/^[0-9]{6}$/.test(code)) throw Error('請輸入六位數驗證碼。');
    const data=await this.call('/api/parent/verify','POST',{code});
    this.unlocked=data.adultAccess===true && Number(data.expiresIn)>0;
    if(!this.unlocked)throw Error('伺服器未核發成人區權限。');
    return true;
  }
  async lock(){
    // Hide locally immediately even if network/server revocation later fails.
    this.unlocked=false;
    try{await this.call('/api/parent/lock','POST',{})}
    catch(e){throw Error('本機已鎖定；伺服器撤銷尚未確認，請登出以撤銷工作階段。')}
    return true;
  }
  discardLocalAccess(){this.unlocked=false}
}
if(typeof window!=='undefined') window.NELUUN_ParentStepUp=ParentStepUpClient;
