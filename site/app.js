import {parseText,analyze,toCSV} from './engine.js';
import {$,h,resource,save,status,fatal} from './ui.js';

let sample='',report=null,inputScope='Synthetic sample';
const resultButtons=['export-json','export-csv'];
function clearResults(message='Inputs changed. Analyze logs to update results.') {
 report=null;for(const id of ['events','failures','sources','alerts-count'])$(id).textContent='—';
 resultButtons.forEach(id=>$(id).disabled=true);
 $('result-badge').textContent='Awaiting analysis';
 $('alerts').innerHTML=`<div class="empty"><span class="muted">${h(message)}</span></div>`;
 $('source-table').replaceChildren();$('parse-details').hidden=true;
}
function dirty(){inputScope='User-selected or edited input; origin not independently verified';clearResults();status('Inputs changed. Select Analyze logs to refresh the results.');}
function run() {
 try {
  const text=$('log-input').value;
  if(new TextEncoder().encode(text).length>1048576)throw new Error('Select a log smaller than 1 MiB.');
  if(!text.trim())throw new Error('Load a sample or paste log records first.');
  const threshold=Number($('threshold').value),windowSeconds=Number($('window').value);
  if(!Number.isInteger(threshold)||threshold<2||threshold>1000||!Number.isInteger(windowSeconds)||windowSeconds<1||windowSeconds>86400)throw new Error('Use a threshold from 2 to 1,000 and a window from 1 to 86,400 seconds.');
  const allowlist=$('allowlist').value.split(',').map(s=>s.trim()).filter(Boolean);
  const loaded=parseText(text,{maxEvents:10000});
  report=analyze(loaded.events,{threshold,windowSeconds,allowlist});
  report.provenance=inputScope;report.parseErrors={errors:loaded.errors,errorCount:loaded.errorCount};
  for(const [id,key] of [['events','totalEvents'],['failures','failures'],['sources','sourceIPs'],['alerts-count','alerts']])$(id).textContent=report.summary[key];
  $('result-badge').textContent=loaded.errorCount?'Review rejected records':'Analysis complete';
  $('alerts').innerHTML=report.alerts.map(a=>`<article class="result-card"><div class="result-title"><h3>${h(a.rule==='failure_burst'?'Failed sign-in burst':'Success after a failure burst')}</h3><span class="badge ${h(a.severity)}">${h(a.severity)}</span></div><div class="meta">${h(a.id)} / ${h(a.ip)}<br>${h(a.timestamp)}</div><p>${h(a.explanation)}</p><details><summary>Inspect source evidence · ${a.evidenceLines.length} record${a.evidenceLines.length===1?'':'s'}</summary><pre>${h(a.evidenceLines.map(n=>`Line ${n}: ${text.split(/\r?\n/)[n-1]}`).join('\n'))}</pre></details></article>`).join('')||`<div class="empty"><strong>${loaded.events.length?'No configured rule matched':'No valid events to analyze'}</strong><span class="muted">${loaded.events.length?'Try a different threshold or time window. A quiet result does not guarantee safety.':'Review the rejected records below and correct the input.'}</span></div>`;
  $('source-table').innerHTML=report.sources.length?`<div class="table-wrap"><table><thead><tr><th>Source IP</th><th>Failed</th><th>Success</th><th>Rule status</th></tr></thead><tbody>${report.sources.map(s=>`<tr><td>${h(s.ip)}</td><td>${s.failures}</td><td>${s.successes}</td><td>${s.allowlisted?'Allowlisted':'Evaluated'}</td></tr>`).join('')}</tbody></table></div>`:'<p class="muted">No valid source addresses.</p>';
  $('parse-details').hidden=!loaded.errorCount;$('parse-details').open=Boolean(loaded.errorCount);
  $('parse-summary').textContent=`${loaded.errorCount} rejected record${loaded.errorCount===1?'':'s'}`;
  $('parse-errors').innerHTML=loaded.errors.map(e=>`<p class="muted">Line ${e.line}: ${h(e.reason)}</p>`).join('');
  resultButtons.forEach(id=>$(id).disabled=false);
  status(`${loaded.events.length} events analyzed. ${report.alerts.length} alerts. ${loaded.errorCount} rejected records.`,Boolean(loaded.errorCount));
 }catch(error){clearResults('Analysis could not complete. Check the input and settings.');status(error.message,true);}
}
function loadSample(){
 let lines=sample.trim().split(/\r?\n/).filter(s=>s.trim()&&!s.trim().startsWith('#'));
 switch($('scenario').value){
  case 'quiet':lines=lines.filter(s=>{const e=JSON.parse(s);return e.src_ip==='192.0.2.20'&&['failure','LOGIN_FAILED'].includes(e.event);});break;
  case 'clean':lines=lines.filter(s=>['success','LOGIN_SUCCESS'].includes(JSON.parse(s).event));break;
  case 'invalid':lines=['{"timestamp": "not-a-date", "event": "LOGIN_FAILED", "src_ip": "192.0.2.10"}','{broken json}','{"timestamp":"2026-08-01T12:00:00Z","event":"LOGIN_FAILED","src_ip":"999.1.1.1"}'];break;
 }
 $('log-input').value=lines.join('\n')+'\n';$('file-input').value='';inputScope='Controlled synthetic authentication sample';run();
}
$('analysis-form').addEventListener('submit',e=>{e.preventDefault();run();});
for(const id of ['log-input','threshold','window','allowlist'])$(id).addEventListener('input',dirty);
$('load-sample').addEventListener('click',loadSample);
$('reset').addEventListener('click',()=>{$('threshold').value=5;$('window').value=300;$('allowlist').value='';$('scenario').value='mixed';loadSample();});
$('file-input').addEventListener('change',async()=>{
 const file=$('file-input').files[0];if(!file)return;
 try{if(file.size>1048576)throw new Error('Select a log smaller than 1 MiB.');$('log-input').value=await file.text();inputScope='Locally selected file; origin not independently verified';run();}catch(error){clearResults();status(error.message,true);}
});
$('export-json').addEventListener('click',()=>{if(report)save('authentication-analysis.json',report);});
$('export-csv').addEventListener('click',()=>{if(report)save('authentication-alerts.csv',toCSV(report),'text/csv');});
try{sample=await resource('sample.jsonl');document.querySelectorAll('[data-ready]').forEach(b=>b.disabled=false);loadSample();}catch(error){fatal(error);}
