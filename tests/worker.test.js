import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';
const url='https://neluun.example';
const request=(path,method='GET',data,origin=url)=>new Request(url+path,{method,
 headers: method==='POST'?{'content-type':'application/json',origin}:{},
 ...(method==='POST'?{body:JSON.stringify(data??{})}:{}) });
const response=async(req,env={})=>{
 const r=await worker.fetch(req,env);return {status:r.status,data:await r.json()};
};
test('GET /api/me without bindings is safely unauthenticated',async()=>{
 const r=await response(request('/api/me'));assert.equal(r.status,200);assert.equal(r.data.authenticated,false);assert.equal(r.data.aiEnabled,false);assert.equal(r.data.childAIEnabled,false);
});
test('Cross-site form posting is rejected',async()=>{
 const r=await response(request('/api/auth/request','POST',{email:'a@example.com'},'https://evil.test'));
 assert.equal(r.status,403);assert.equal(r.data.error,'origin_required');
});
test('Email login without configuration fails closed',async()=>{
 const r=await response(request('/api/auth/request','POST',{email:'a@example.com'}));
 assert.equal(r.status,503);assert.equal(r.data.error,'not_configured');
});
test('AI without configuration fails closed and never calls upstream',async()=>{
 const r=await response(request('/api/chat','POST',{mode:'personal',message:'您好'}));
 assert.equal(r.status,503);assert.equal(r.data.error,'ai_disabled');
});
test('All unknown API endpoints return 404',async()=>{
 const r=await response(request('/api/unknown','POST',{}));assert.equal(r.status,404);
});
test('No API response is cacheable',async()=>{
 const r=await worker.fetch(request('/api/me'),{});assert.equal(r.headers.get('cache-control'),'no-store');
});
