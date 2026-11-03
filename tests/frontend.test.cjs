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

test('partial report keeps observed calls separate from absent function findings',async()=>{
 // Synthetic UI-schema reproduction of a partial report; not an on-chain fixture.
 const calls=Array.from({length:34},(_,i)=>({function:'observed_'+i,address:'0x'+String(i).padStart(40,'0'),params:'calldata_'+i}));
 const report={transaction_hash:'0x123',analysis_status:'partial',sections:{function_analysis:'failed',scoring:'skipped'},scored_functions:[],evidence_cards:[],function_analysis:{functions_to_inspect:{function_name_with_hash:calls}},model_endpoint:{failure:{kind:'rate_limited',http_status:429}}};
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'partialcalls'}},'/console/api/result/partialcalls':{data:report}});await settle();
 await app.elements['analysis-form'].listeners.submit({preventDefault(){}});app.streams[0].emit('error','Model endpoint returned HTTP 429','1');app.streams[0].emit('end',{},'2');await settle();
 const walk=el=>[el,...el.children.flatMap(walk)];let nodes=walk(app.elements.results);let content=collect(app.elements.results);
 assert.match(content,/Functions and evidence \(0\)/);assert.match(content,/Observed calls \/ unanalysed candidates \(34\)/);assert.match(content,/INCONCLUSIVE/);
 assert.equal(nodes.filter(n=>n.className==='finding').length,0);assert.equal(nodes.filter(n=>n.className==='observed-call').length,20);
 assert.doesNotMatch(content,/Full finding and evidence/);assert.match(content,/Showing 20 of 34 observed calls/);
 const more=nodes.find(n=>n.textContent==='Show 20 more observed calls');more.onclick();nodes=walk(app.elements.results);content=collect(app.elements.results);
 assert.equal(nodes.filter(n=>n.className==='observed-call').length,34);assert.match(content,/Showing 34 of 34 observed calls/);assert.equal(more.hidden,true);
 assert.ok(nodes.some(n=>n.tagName==='pre'&&n.textContent.includes('"function_name_with_hash"')&&n.textContent.includes('observed_33')));
 assert.ok(nodes.some(n=>n.textContent==='Download report JSON'));
});

test('scored findings do not hide separately labelled observed calls',async()=>{
 // Synthetic UI schema: a genuine scored entry and an unanalysed candidate coexist.
 const report={transaction_hash:'0x123',analysis_status:'completed',scored_functions:[{function:'scored_fn',evidence:['Scored evidence']}],evidence_cards:[],function_analysis:{functions_to_inspect:{function_name_with_hash:[{function:'candidate_only'}]}}};
 const app=boot({'/console/api/config':{data:config},'/console/api/capture':{data:report}});await settle();await app.elements['capture-button'].onclick();
 const walk=el=>[el,...el.children.flatMap(walk)],nodes=walk(app.elements.results),content=collect(app.elements.results);
 assert.match(content,/Functions and evidence \(1\)/);assert.match(content,/Observed calls \/ unanalysed candidates \(1\)/);
 assert.equal(nodes.filter(n=>n.className==='finding').length,1);assert.equal(nodes.filter(n=>n.className==='observed-call').length,1);
 const finding=nodes.find(n=>n.className==='finding'),observation=nodes.find(n=>n.className==='observed-call');
 assert.match(collect(finding),/scored_fn/);assert.doesNotMatch(collect(finding),/candidate_only/);assert.match(collect(observation),/candidate_only/);
 assert.doesNotMatch(collect(observation),/Full finding and evidence/);
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


for (const [code,explanation] of [['free_model_monthly_limit','monthly allowance'],['free_model_tpm_limit','token-rate'],['provider_rate_limit','capacity']]) {
 test(`rate-limit report exposes recognized recovery category ${code}`,async()=>{
  const report={transaction_hash:'0x123',analysis_status:'partial',sections:{function_analysis:'failed',scoring:'skipped'},model_endpoint:{failure:{kind:'rate_limited',http_status:429,provider_code:code,retry_after_seconds:120}}};
  const app=boot({'/console/api/config':{data:config},'/console/api/capture':{data:report}});await settle();await app.elements['capture-button'].onclick();
  const content=collect(app.elements.results);
  assert.match(content,/INCONCLUSIVE/);assert.ok(content.includes(`Provider code: ${code}`));
  assert.ok(content.includes(explanation));assert.match(content,/Retry-After at failure: 120 seconds/);
 });
}

test('unknown measurements do not appear as zero scores or a successful verdict',async()=>{
 const report={transaction_hash:'0x123',analysis_status:'completed',classification:{rule_verdict:'INCONCLUSIVE',priority_score:null,reentrancy:{score:null},signals:{profit_extraction_eth:null,large_transfer_to_eoa:null}}};
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'unknowns'}},'/console/api/result/unknowns':{data:report}});await settle();
 await app.elements['analysis-form'].listeners.submit({preventDefault(){}});app.streams[0].emit('end',{},'1');await settle();
 const content=collect(app.elements.results);assert.match(content,/INCONCLUSIVE/);assert.doesNotMatch(content,/Reported scores/);
});


test('terminal event with inherited duplicate ID still retrieves report',async()=>{
 const report={transaction_hash:'0x123',analysis_status:'partial',classification:{rule_verdict:'INCONCLUSIVE'}};
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'endgap'}},'/console/api/result/endgap':{data:report}});await settle();
 await app.elements['analysis-form'].listeners.submit({preventDefault(){}});
 app.streams[0].emit('log','last log','5');
 app.streams[0].emit('end',{},'5'); // EventSource inherits the last id when the server omits it.
 await settle();assert.match(collect(app.elements.results),/INCONCLUSIVE/);
});

test('replay gaps remain visible even when EventSource inherits an old ID',async()=>{
 const app=boot({'/console/api/config':{data:config},'/console/api/analyze':{data:{run_id:'loggap'}}});await settle();
 await app.elements['analysis-form'].listeners.submit({preventDefault(){}});
 app.streams[0].emit('log','recent','5');
 app.streams[0].emit('replay-gap',{message:'Older technical logs expired'},'5');
 assert.match(collect(app.elements.activity),/Older technical logs expired/);
 app.streams[0].emit('heartbeat',{},'5');assert.match(app.elements.connection.textContent,/Connected/);
});


test('paired scored targets and evidence cards render once without hiding distinct evidence',async()=>{
 const report={transaction_hash:'0x123',analysis_status:'completed',
 scored_functions:[{function:'0x12345678',address:'0xAbC',evidence:['score evidence']}],
 evidence_cards:[{function_signature:{function:'0x12345678',address:'0xabc'},evidence:['card evidence']},
 {function_signature:{function:'0x12345678',address:'0xdef'},evidence:['other address evidence']}],
 function_analysis:{functions_to_inspect:{function_name_with_hash:[{function:'0x12345678',address:'0xabc'},{function:'0x99999999',address:'0xabc'}]}}};
 const app=boot({'/console/api/config':{data:config},'/console/api/capture':{data:report}});await settle();await app.elements['capture-button'].onclick();
 const content=collect(app.elements.results);
 assert.match(content,/Functions and evidence \(2\)/);
 assert.match(content,/Observed calls \/ unanalysed candidates \(1\)/);
 for(const marker of ['score evidence','card evidence','other address evidence']) assert.ok(content.includes(marker));
});
