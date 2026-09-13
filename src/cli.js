import { readFile, writeFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parseText, analyze, toCSV, toHTML } from './analyzer.js';

const help = `Security Log Analyzer 2
node src/cli.js --input FILE [options]
  --input-format auto|jsonl|legacy|ssh    Default auto
  --output-format text|json|csv|html     Default text
  --output FILE                        Default stdout
  --threshold N                        Default 5, minimum 2
  --window-seconds N                   Default 300
  --year YYYY                          Required for yearless SSH syslog (UTC)
  --allowlist FILE                     JSON array of exact source IPs
  --strict                             Exit 3 on any rejected line
  --fail-on-alert                      Exit 2 if alerts are found
  --max-events N                       Default 100000
  --help
Maximum input size: 64 MiB. JSON/ISO timestamps must include a timezone.
Exit codes: 0 completed, 1 usage/I/O error, 2 alerts, 3 strict parsing error.`;

try {
  const opts = {};
  const flags = new Set(['strict','fail-on-alert','help']);
  const names = new Set(['input','input-format','output-format','output','threshold','window-seconds','year','allowlist','max-events',...flags]);
  for (let i=2;i<process.argv.length;i++) {
    const key=process.argv[i].replace(/^--/,'');
    if (!process.argv[i].startsWith('--') || !names.has(key)) throw new Error(`Unknown option: ${process.argv[i]}`);
    if (Object.hasOwn(opts,key)) throw new Error(`Duplicate option: --${key}`);
    if (flags.has(key)) opts[key]=true;
    else { if (!process.argv[i+1] || process.argv[i+1].startsWith('--')) throw new Error(`Missing value: --${key}`); opts[key]=process.argv[++i]; }
  }
  if (opts.help) { console.log(help); process.exit(0); }
  if (!opts.input) throw new Error('Specify --input FILE; use --help for options');
  const inputStat=await stat(opts.input);
  if (inputStat.size>64*1024*1024) throw new Error('File exceeds 64 MiB limit');
  if (opts.output) {
    const outputStat=await stat(opts.output).catch(error=>{if(error.code==='ENOENT')return null;throw error;});
    if (resolve(opts.input)===resolve(opts.output) || (outputStat && inputStat.dev===outputStat.dev && inputStat.ino===outputStat.ino)) throw new Error('Output must not overwrite the input log');
  }
  for (const key of ['threshold','window-seconds','year','max-events']) if (opts[key]!==undefined && !/^\d+$/.test(opts[key])) throw new Error(`--${key} requires a positive integer`);
  const parsed=parseText(await readFile(opts.input,'utf8'),{format:opts['input-format']??'auto',year:opts.year===undefined?undefined:Number(opts.year),maxEvents:Number(opts['max-events']??100000)});
  if (opts.strict && parsed.errorCount) { console.error(JSON.stringify({error:'Rejected log lines',...parsed,events:undefined},null,2)); process.exit(3); }
  const allowlist=opts.allowlist?JSON.parse(await readFile(opts.allowlist,'utf8')):[];
  if (!Array.isArray(allowlist)) throw new Error('Allowlist must be a JSON array');
  const report=analyze(parsed.events,{threshold:Number(opts.threshold??5),windowSeconds:Number(opts['window-seconds']??300),allowlist});
  report.parseErrors={errorCount:parsed.errorCount,examples:parsed.errors};
  const format=opts['output-format']??'text';
  let output;
  if (format==='json') output=JSON.stringify(report,null,2)+'\n';
  else if (format==='csv') output=toCSV(report);
  else if (format==='html') output=toHTML(report);
  else if (format==='text') output=`Events: ${report.summary.totalEvents}\nFailures: ${report.summary.failures}\nSuccesses: ${report.summary.successes}\nRejected lines: ${parsed.errorCount}\nAlerts: ${report.alerts.length}\n`+report.alerts.map(a=>`${a.id} ${a.rule} ${a.ip} ${a.timestamp}`).join('\n')+'\n';
  else throw new Error('Unsupported output format');
  if (opts.output) await writeFile(opts.output,output,'utf8'); else process.stdout.write(output);
  if (parsed.errorCount) console.error(`Warning: rejected ${parsed.errorCount} line(s); see JSON output for details.`);
  if (opts['fail-on-alert'] && report.alerts.length) process.exitCode=2;
} catch(error) { console.error(`Error: ${error.message}`); process.exitCode=1; }
