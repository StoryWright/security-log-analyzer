import { performance } from 'node:perf_hooks';
import { mkdir,writeFile } from 'node:fs/promises';
import { analyze } from '../src/analyzer.js';
const samples=[];
for(const n of [10000,100000]) {
 const events=Array.from({length:n},(_,i)=>({id:`bench-${i}`,line:i+1,time:Date.UTC(2026,0,1)+i*1000,type:i%10?'success':'failure',ip:`192.0.2.${i%200+1}`,user:'synthetic'}));
 const before=process.memoryUsage().heapUsed,t=performance.now();
 const report=analyze(events);
 samples.push({events:n,elapsedMs:Number((performance.now()-t).toFixed(2)),heapDeltaBytes:process.memoryUsage().heapUsed-before,alerts:report.alerts.length});
}
const result={node:process.version,platform:process.platform,architecture:process.arch,scope:'One local run of analyze() on synthetic in-memory events. Excludes parsing/I/O. Timing and heap deltas vary and are not a scalability guarantee.',samples};
await mkdir(new URL('../reports/',import.meta.url),{recursive:true});
await writeFile(new URL('../reports/benchmark.json',import.meta.url),JSON.stringify(result,null,2));
console.log(JSON.stringify(result,null,2));
