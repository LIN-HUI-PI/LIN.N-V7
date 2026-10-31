/**
 * NELUUN V9.5 isolated Cloudflare Worker build. No production deployment.
 * Cloudflare Workers Builds:
 *   Build command: node scripts/prepare_v95_worker.mjs
 *   Deploy command: npx wrangler deploy --config wrangler.v95.generated.jsonc
 *   Build variable: NELUUN_V95_TEST_D1_ID (ID of dedicated test D1 only)
 * Never put keys or real D1 IDs into git.
 */
import {mkdtempSync,cpSync,readFileSync,writeFileSync,rmSync,existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

const TEST_WORKER='neluun-v95-auth-test';
const TEST_DB='neluun-v95-auth-isolated-test';
const BRANCH='neluun-v9-5-safety';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const id=(process.env.NELUUN_V95_TEST_D1_ID||'').trim();
if(!uuid.test(id))throw Error('Missing dedicated V9.5 TEST D1 ID build variable. Nothing deployed.');
if(process.env.WORKERS_CI && process.env.WORKERS_CI_BRANCH!==BRANCH)
 throw Error('Unsafe Git branch for staging deploy. Nothing deployed.');
const source='public/index.html',patch='.github/workflows/apply_neluun_v95.py';
if(!existsSync(source)||!existsSync(patch)||!existsSync('public/v95_parent_client.js'))
 throw Error('Incomplete V9.5 source. Nothing deployed.');
const dist='v95-preview';
const temp=mkdtempSync(join(tmpdir(),'neluun-v95-build-'));
try{
  cpSync('public',dist,{recursive:true,force:true});
  execFileSync('python3',[patch,source,'--output',join(dist,'index.html')],{stdio:'pipe'});
  const markup=readFileSync(join(dist,'index.html'),'utf8');
  const checks=['V9.5 · FAMILY SAFETY PREVIEW','NELUUN_V95_GUARD','v95CheckCode','v95_parent_client.js','v95RequireServer'];
  if(!checks.every(check=>markup.includes(check)))throw Error('V9.5 PIN/OTP security gate incomplete');
  const legacy=readFileSync(source,'utf8');
  if(!legacy.includes('V9.4 · SAFE CONNECTION'))throw Error('Expected unchanged V9.4 baseline');
  const swPath=join(dist,'sw.js');
  if(existsSync(swPath)){
    let sw=readFileSync(swPath,'utf8');
    // Separate test cache, and avoid old V9.4 install caching stale pages.
    sw=sw.replaceAll('neluun-v9-4-safe-backup-20261030','neluun-v9-5-family-safety-preview-20261101');
    writeFileSync(swPath,sw);
  }
  // Inline HTML JS syntax check; the external client is checked separately by npm test.
  const embedded=markup.split('<script>').pop().split('</script>')[0];
  const jsCheck=join(temp,'inline.js');
  writeFileSync(jsCheck,embedded);
  execFileSync(process.execPath,['--check',jsCheck],{stdio:'pipe'});
  const config={
    name:TEST_WORKER,
    main:'./src/v95_parent_api.js',
    compatibility_date:'2026-10-23',
    assets:{directory:'./v95-preview',binding:'ASSETS',run_worker_first:['/api/*']},
    d1_databases:[{binding:'DB',database_name:TEST_DB,database_id:id,migrations_dir:'migrations'}],
    vars:{AI_ENABLED:'false',PARENT_STEP_UP_ENABLED:'false',GLOBAL_AI_DAILY_LIMIT:'0',GLOBAL_AI_MONTHLY_LIMIT:'0'}
  };
  writeFileSync('wrangler.v95.generated.jsonc',JSON.stringify(config,null,2)+'\n');
  console.log('Prepared isolated V9.5 Worker assets and config. No deployment performed.');
}catch(e){
  try{rmSync('wrangler.v95.generated.jsonc',{force:true})}catch{}
  throw e;
}finally{rmSync(temp,{recursive:true,force:true})}
