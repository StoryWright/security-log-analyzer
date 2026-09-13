import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLine, parseText, analyze, timestamp, toCSV, toHTML, canonicalIP } from '../src/analyzer.js';

const base=Date.parse('2026-08-01T12:00:00Z');
const event=(sec,type='failure',ip='192.0.2.10',line=sec+1)=>parseLine(JSON.stringify({timestamp:new Date(base+sec*1000).toISOString(),event:type,src_ip:ip,user:'lab_alex'}),line);

test('legacy format stays compatible with original project',()=>assert.equal(parseLine('2026-08-01 12:00:00 LOGIN_FAILED 192.0.2.1').type,'failure'));
test('parses ISO OpenSSH failure with invalid user',()=>assert.equal(parseLine('2026-08-01T12:00:00Z host sshd[42]: Failed password for invalid user lab_alex from 192.0.2.2 port 4567 ssh2').user,'lab_alex'));
test('parses accepted public key login',()=>assert.equal(parseLine('2026-08-01T12:00:00+00:00 host sshd[4]: Accepted publickey for lab_alex from 2001:db8::1 port 99 ssh2').type,'success'));
test('requires year for classic syslog',()=>assert.throws(()=>parseLine('Aug  1 12:00:00 host sshd[2]: Failed password for a from 192.0.2.1 port 55 ssh2'),/--year/));
test('parses classic syslog with explicit year',()=>assert.equal(parseLine('Aug  1 12:00:00 host sshd: Failed password for a from 192.0.2.1 port 55 ssh2',1,{year:2026}).time,base));
for (const invalid of ['2026-02-30T12:00:00Z','2025-02-29T12:00:00Z','2026-13-01T00:00:00Z','2026-01-01T24:00:00Z','2026-01-01T12:60:00Z','2026-01-01T12:00:61Z','2026-01-01T12:00:00','2026-01-01T00:00:00+99:00'])
  test(`rejects invalid date ${invalid}`,()=>assert.throws(()=>timestamp(invalid)));
test('accepts a valid leap day and equivalent timezone',()=>assert.equal(timestamp('2024-02-29T14:00:00+02:00'),timestamp('2024-02-29T12:00:00Z')));
test('canonicalizes IPv6 spellings',()=>assert.equal(canonicalIP('2001:0db8:0:0:0:0:0:1'),'2001:db8::1'));
test('rejects invalid IPv4',()=>assert.throws(()=>canonicalIP('999.0.0.1')));
test('rejects inherited event property names',()=>assert.throws(()=>parseLine('{"timestamp":"2026-08-01T12:00:00Z","event":"__proto__","ip":"192.0.2.1"}')));
test('skips blanks, reports malformed lines, does not echo raw data',()=>{ const p=parseText('# synthetic\nnot-a-log\n\n'); assert.equal(p.events.length,0); assert.equal(p.errorCount,1); assert.equal(p.errors[0].line,2); assert.ok(!JSON.stringify(p.errors).includes('not-a-log')); });
test('caps error examples without hiding total',()=>{const p=parseText(Array(50).fill('bad').join('\n')); assert.equal(p.errorCount,50);assert.equal(p.errors.length,20);});
test('malformed JSON errors do not disclose log fragments',()=>{const p=parseText('{"private":"DO_NOT_DISCLOSE" broken}');assert.equal(p.errorCount,1);assert.ok(!JSON.stringify(p.errors).includes('DO_NOT_DISCLOSE'));});
test('invalid input format is rejected even on empty input',()=>assert.throws(()=>parseText('',{format:'unknown'}),/Unsupported input/));
test('enforces event limit',()=>assert.throws(()=>parseText('2026-08-01 12:00:00 LOGIN_FAILED 192.0.2.1\n2026-08-01 12:00:01 LOGIN_FAILED 192.0.2.1',{maxEvents:1}),/exceeds/));
test('no alert under threshold',()=>assert.equal(analyze([0,1,2,3].map(s=>event(s))).alerts.length,0));
test('five failures create one burst alert with exact evidence',()=>{const r=analyze([0,20,40,60,80].map(s=>event(s)));assert.equal(r.alerts.length,1);assert.equal(r.alerts[0].attempts,5);assert.deepEqual(r.alerts[0].evidenceLines,[1,21,41,61,81]);});
test('window boundary is inclusive',()=>assert.equal(analyze([0,100,200,250,300].map(s=>event(s))).alerts.length,1));
test('failures outside window do not accumulate',()=>assert.equal(analyze([0,100,200,250,301].map(s=>event(s))).alerts.length,0));
test('separate IPs cannot combine into one burst',()=>assert.equal(analyze([event(1),event(2),event(3),event(4,'failure','192.0.2.20'),event(5,'failure','192.0.2.20')]).alerts.length,0));
test('input ordering does not change detections',()=>assert.deepEqual(analyze([0,1,2,3,4].map(s=>event(s))).alerts,analyze([4,0,2,1,3].map(s=>event(s))).alerts));
test('sustained burst is deduplicated',()=>assert.equal(analyze(Array.from({length:15},(_,i)=>event(i))).alerts.length,1));
test('a later independent burst raises a second alert',()=>assert.equal(analyze([0,1,2,3,4,1000,1001,1002,1003,1004].map(s=>event(s))).alerts.length,2));
test('success after burst is correlated once',()=>{const r=analyze([...Array.from({length:5},(_,i)=>event(i)),event(5,'success'),event(6,'success')]);assert.equal(r.alerts.length,2);assert.equal(r.alerts[1].rule,'success_after_burst');});
test('late success is not correlated',()=>assert.equal(analyze([...Array.from({length:5},(_,i)=>event(i)),event(605,'success')]).alerts.length,1));
test('allowlist suppresses alerts but retains counts',()=>{const r=analyze([0,1,2,3,4].map(s=>event(s)),{allowlist:['192.0.2.10']});assert.equal(r.alerts.length,0);assert.equal(r.summary.failures,5);});
test('empty data has explicit zero totals',()=>assert.deepEqual(analyze([]).summary,{totalEvents:0,failures:0,successes:0,sourceIPs:0,alerts:0}));
test('invalid detection configuration is rejected',()=>{for(const options of [{threshold:1},{windowSeconds:0},{successWindowSeconds:-1}])assert.throws(()=>analyze([],options));});
test('HTML escapes hostile report values',()=>{const r=analyze([0,1,2,3,4].map(s=>event(s)));r.alerts[0].explanation='<script>alert(1)</script>';assert.ok(!toHTML(r).includes('<script>'));assert.ok(toHTML(r).includes('&lt;script&gt;'));});
test('CSV escapes quotes, commas, and spreadsheet formulas',()=>{const r=analyze([0,1,2,3,4].map(s=>event(s)));r.alerts[0].explanation='=SUM(1,2) "x"';assert.ok(toCSV(r).includes('"\'=SUM(1,2) ""x"""'));});

test('CLI returns useful statuses and exports JSON from another working directory',()=>{
 const dir=mkdtempSync(join(tmpdir(),'story-log-test-'));
 try {
  const input=join(dir,'auth.log');writeFileSync(input,'2026-08-01 12:00:00 LOGIN_FAILED 192.0.2.1\n2026-08-01 12:00:01 LOGIN_FAILED 192.0.2.1\n');
  const cli=fileURLToPath(new URL('../src/cli.js',import.meta.url));
  const run=args=>spawnSync(process.execPath,[cli,...args],{cwd:dir,encoding:'utf8'});
  let r=run(['--input',input,'--threshold','2','--output-format','json','--fail-on-alert']);assert.equal(r.status,2);assert.equal(JSON.parse(r.stdout).summary.alerts,1);
  const original=readFileSync(input,'utf8');r=run(['--input',input,'--output',input]);assert.equal(r.status,1);assert.match(r.stderr,/overwrite/);assert.equal(readFileSync(input,'utf8'),original);
  writeFileSync(input,'malformed\n');r=run(['--input',input,'--strict']);assert.equal(r.status,3);
  r=run(['--bogus']);assert.equal(r.status,1);assert.match(r.stderr,/Unknown option/);
  r=run(['--input',join(dir,'missing')]);assert.equal(r.status,1);
 } finally { assert.equal(dirname(resolve(dir)),resolve(tmpdir()));assert.ok(basename(dir).startsWith('story-log-test-'));rmSync(dir,{recursive:true,force:true}); }
});
