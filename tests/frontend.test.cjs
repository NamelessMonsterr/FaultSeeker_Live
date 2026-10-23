// Run with node --test tests/frontend.test.cjs. No browser dependencies.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
class Element {
  constructor(tag='div'){this.tagName=tag;this.children=[];this.hidden=false;this.value='';this.textContent='';this.type='password';this.listeners={};this.disabled=false;this.id='';}
  append(...items){this.children.push(...items);this.lastChild=this.children.at(-1);}
  prepend(item){this.children.unshift(item);}
  replaceChildren(...items){this.children=items;}
  setAttribute(key,value){this[key]=value;}
  addEventListener(key,fn){this.listeners[key]=fn;}
  reportValidity(){return true;}
  after(){} remove(){} click(){}
  get classList(){return {add(){}};}
}
function boot(routes){
 const elements={};const storage=new Map();const streams=[];const requests=[];
 for(const match of fs.readFileSync('app/web/index.html','utf8').matchAll(/id="([^"]+)"/g)) elements[match[1]]=new Element();
 const document={baseURI:'https://example.com/console/',getElementById(id){return elements[id]??=new Element();},createElement(tag){return new Element(tag);}};
 class EventSource{constructor(url){this.url=String(url);this.handlers={};streams.push(this);}addEventListener(key,fn){this.handlers[key]=fn;}close(){this.closed=true;}emit(key,data,id=''){this.handlers[key]?.({data:JSON.stringify(data),lastEventId:id});}}
 const context={document,window:{addEventListener(){}},URL,Blob,console,Date,EventSource,setTimeout(fn){fn();},setInterval(){return 1;},clearInterval(){},sessionStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},fetch:async(url,options)=>{const path=new URL(url).pathname;requests.push({path,options});const result=routes[path]??{status:404,data:{error:'not found'}};return {ok:!result.status||result.status<400,status:result.status||200,json:async()=>result.data};}};
 vm.runInNewContext(fs.readFileSync('app/web/assets/console.js','utf8'),context);
 return {elements,streams,requests,storage};
}
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const config={chains:['eth'],models:[{id:'no-llm',label:'Deterministic',keyEnv:null}],repo_present:true,capture_available:true};
function collect(el){return `${el.textContent} ${el.children.map(collect).join(' ')}`;}
test('setup uses relative API and never stores request keys; stream stages do not prematurely mark final report done',async()=>{
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'abc123'}}});await settle();
 const e=app.elements;e.transaction.value='0x'+'1'.repeat(64);e.chain.value='eth';e.model.value='no-llm';e['model-key'].value='SECRET';e['rpc-key'].value='RPC_SECRET';
 await e['analysis-form'].listeners.submit({preventDefault(){}});
 assert.equal(e.running.hidden,false);assert.equal(e['model-key'].value,'');assert.equal(e['rpc-key'].value,'');assert.ok(![...app.storage.values()].join('').includes('SECRET'));
 const stream=app.streams[0];stream.emit('stage',{index:3},'1');assert.match(collect(e.stepper),/03  Rule analysis In progress/);stream.emit('stage',{index:4},'2');assert.match(collect(e.stepper),/04  Function analysis In progress/);assert.match(collect(e.stepper),/05  Final report Pending/);
 assert.equal(JSON.parse(app.requests.find(r=>r.path.endsWith('analyze')).options.body).replay,false);
});
test('raw pipeline report renders safely after end without transaction object',async()=>{
 const payload='<img src=x onerror=alert(1)>';
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'abc123'}},'/console/api/result/abc123':{data:{transaction_hash:'0x123',analysis_status:'completed',scored_functions:[{function:payload,evidence:['Observed call']}],limitations:[]}}});await settle();const e=app.elements;e.model.value='no-llm';await e['analysis-form'].listeners.submit({preventDefault(){}});app.streams[0].emit('end',{},'1');await settle();assert.equal(e.results.hidden,false);assert.match(collect(e.results),/Investigation report/);assert.match(collect(e.results),/REVIEW FINDINGS/);assert.ok(collect(e.results).includes(payload));assert.doesNotMatch(collect(e.results),/CLEAN|CONFIRMED/);
});
test('failed result remains a visible inconclusive state rather than blank page',async()=>{
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'abc123'}}});await settle();await app.elements['analysis-form'].listeners.submit({preventDefault(){}});app.streams[0].emit('error','Provider unavailable','1');app.streams[0].emit('end',{},'2');await settle();assert.equal(app.elements.running.hidden,false);assert.equal(app.elements['active-task'].textContent,'No report available');assert.match(app.elements.notice.textContent,/does not indicate a clean transaction/);
});
test('explicit saved capture preserves deterministic scope and exposes underlying evidence',async()=>{
 const app=boot({'/console/api/config':{data:config},'/console/api/capture':{data:{transaction:{hash:'0x123'},analysis_mode:'no-llm-free-rpc',analysis_status:'stage1_complete',classification:{rule_verdict:'EXPLOIT'},query_records:[{trace:'observed'}],limitations:['Trace scope only']}}});await settle();await app.elements['capture-button'].onclick();const content=collect(app.elements.results);assert.match(content,/SAVED CAPTURE/);assert.match(content,/EXPLOIT \/ STAGE 1 ONLY/);assert.match(content,/LLM function analysis was not performed/);assert.match(content,/observed/);assert.ok(!app.requests.some(r=>r.path.endsWith('/analyze')));
});
test('configuration failure disables live submit and exposes error',async()=>{
 const app=boot({});await settle();assert.match(app.elements.notice.textContent,/Live configuration unavailable/);assert.equal(app.elements.environment.textContent,'SERVICE UNAVAILABLE');
});

test('a pipeline error cannot display a successful report even when a partial file exists',async()=>{
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'abc123'}},'/console/api/result/abc123':{data:{transaction_hash:'0x123',analysis_status:'completed',classification:{rule_verdict:'CLEAN'}}}});await settle();await app.elements['analysis-form'].listeners.submit({preventDefault(){}});app.streams[0].emit('error','Run cancelled','1');app.streams[0].emit('end',{},'2');await settle();const content=collect(app.elements.results);assert.match(content,/Investigation .* interrupted/);assert.match(content,/INCONCLUSIVE/);assert.match(content,/Run cancelled/);
});
test('HTTP 200 error payload is rejected as a report',async()=>{
 const app=boot({'/console/api/config':{data:config},'/console/api/capture':{data:{error:'not ready'}}});await settle();await app.elements['capture-button'].onclick();assert.match(app.elements.notice.textContent,/report format is invalid/);
});


test('large forensic reports paginate findings without dropping downloadable report data',async()=>{
 const functions=Array.from({length:803},(_,i)=>({function:'function_'+i,evidence:['Observed call '+i]}));
 const app=boot({'/console/api/config':{data:config},'/console/api/capture':{data:{transaction_hash:'0x123',analysis_status:'completed',scored_functions:functions}}});await settle();await app.elements['capture-button'].onclick();
 const walk=el=>[el,...el.children.flatMap(walk)];let nodes=walk(app.elements.results);assert.equal(nodes.filter(n=>n.tagName==='article').length,20);assert.match(collect(app.elements.results),/Showing 20 of 803 findings/);
 const button=nodes.find(n=>n.textContent==='Show 20 more findings');button.onclick();nodes=walk(app.elements.results);assert.equal(nodes.filter(n=>n.tagName==='article').length,40);assert.match(collect(app.elements.results),/Showing 40 of 803 findings/);
});

test('model retry status explicitly pauses analysis and never completes pending stages',async()=>{
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'retryrun'}}});await settle();
 await app.elements['analysis-form'].listeners.submit({preventDefault(){}});
 app.streams[0].emit('model_status',{state:'waiting_on_model_endpoint',phase:'preflight',http_status:502,retry_in_seconds:2},'1');
 assert.equal(app.elements['active-task'].textContent,'Waiting on model endpoint');
 assert.match(app.elements.connection.textContent,/retry in 2s/);
 assert.match(collect(app.elements.stepper),/Final report Pending/);
 app.streams[0].emit('model_status',{state:'model_endpoint_ready',phase:'preflight'},'2');
 assert.equal(app.elements['active-task'].textContent,'Model endpoint ready');
});

test('partial endpoint-failure report visibly lists failed and skipped sections',async()=>{
 const report={transaction_hash:'0x123',analysis_status:'partial',classification:{rule_verdict:'INCONCLUSIVE'},sections:{deterministic_checks:'completed',function_analysis:'failed',scoring:'skipped'},model_endpoint:{failure:{kind:'upstream_http',http_status:502,message:'Model endpoint returned an upstream HTTP error.'}}};
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'lossrun'}},'/console/api/result/lossrun':{data:report}});await settle();
 await app.elements['analysis-form'].listeners.submit({preventDefault(){}});app.streams[0].emit('error','Model endpoint returned HTTP 502','1');app.streams[0].emit('end',{},'2');await settle();
 const content=collect(app.elements.results);assert.match(content,/Investigation .* partial/);assert.match(content,/Analysis coverage/);assert.match(content,/function analysis.*failed/);assert.match(content,/scoring.*skipped/);assert.match(content,/INCONCLUSIVE/);assert.doesNotMatch(content,/Investigation report/);
});
