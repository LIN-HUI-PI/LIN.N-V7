import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const build=()=>{
 const dir=mkdtempSync(join(tmpdir(),'neluun-v95-'));
 try{
  const target=join(dir,'index.html');
  execFileSync('python3',['.github/workflows/apply_neluun_v95.py','public/index.html','--output',target],{stdio:'pipe'});
  const html=readFileSync(target,'utf8');
  return {html,js:html.match(/<script>([\s\S]*?)<\/script>/)?.[1],dir};
 }catch(e){rmSync(dir,{recursive:true,force:true});throw e}
};
test('V9.5 preview includes server-authorized OTP step before PIN or encrypted-vault unlock',()=>{
 const {html,js,dir}=build();
 try{
  assert.match(html,/V9\.5 · FAMILY SAFETY PREVIEW/);
  assert.match(html,/src="\.\/v95_parent_client\.js"/);
  assert.match(js,/function v95Gate\(\)/);
  assert.match(js,/function v95RequireServer\(\)/);
  assert.match(js,/await v95RequireServer\(\)/);
  assert.match(js,/v95CheckCode\(form\)/);
  assert.match(js,/data-form="v95CheckCode"/);
  assert.match(js,/v95Client\(\)\.challenge\(\)/);
  assert.match(js,/v95Client\(\)\.verify\(code\)/);
  assert.match(js,/v95ParentClient\.lock\(\)/);
  assert.match(js,/s\.v95Unlocked=false/);
  assert.match(js,/document\.addEventListener\('visibilitychange'/);
  const check=join(dir,'preview-syntax.js');writeFileSync(check,js,'utf8');
  execFileSync(process.execPath,['--check',check],{stdio:'pipe'});
 }finally{rmSync(dir,{recursive:true,force:true})}
});
test('API guard is present in server, not just hidden by navigation UI',()=>{
 const server=readFileSync('src/v95_parent_api.js','utf8');
 assert.match(server,/const sensitiveOld/);
 assert.match(server,/pathname === '\/api\/chat'/);
 assert.match(server,/pathname === '\/api\/guardian\/declare'/);
 assert.match(server,/pathname === '\/api\/guardian\/withdraw'/);
 assert.match(server,/await access\(env, user\)/);
 assert.match(server,/adult_locked/);
});
