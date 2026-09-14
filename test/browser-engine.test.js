import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {isIP as nodeIP} from 'node:net';
import * as cli from '../src/analyzer.js';
import {buildSite} from '../scripts/build-site.mjs';
await buildSite();
const browser=await import('../_site/engine.js');
const {isIP}=await import('../site/platform.js');
const fixture=await readFile(new URL('../fixtures/auth-demo.jsonl',import.meta.url),'utf8');

test('browser analyzer matches CLI parsing, detections, and exports across rule changes',()=>{
 const parsed=browser.parseText(fixture);assert.deepEqual(parsed,cli.parseText(fixture));
 for(const settings of [{},{threshold:6},{windowSeconds:1800},{allowlist:['192.0.2.10']}]){
  const report=browser.analyze(parsed.events,settings);
  assert.deepEqual(report,cli.analyze(parsed.events,settings));assert.equal(browser.toCSV(report),cli.toCSV(report));
 }
 assert.equal(browser.analyze(parsed.events).alerts.length,2);
 assert.equal(browser.analyze(parsed.events,{threshold:6}).alerts.length,0);
});
test('browser IP adapter agrees with Node on documented addresses and rejects malformed inputs',()=>{
 const values=['192.0.2.10','0.0.0.0','255.255.255.255','256.1.1.1','01.2.3.4','127.1','1.2.3','1.2.3.4.5','1.2.3.-1','1.2.3. 4','0x7f.0.0.1','1.2.3.4\n','::','::1','2001:db8::1','2001:0DB8:0000:0000:0000:0000:0000:0001','::ffff:192.0.2.1','::ffff:192.00.2.1','1:2:3:4:5:6:7:8','1:2:3:4:5:6:7','1:2:3:4:5:6:7:8:9','2001:::1','2001::db8::1','[::1]','bad','','https://example.com'];
 for(const value of values)assert.equal(isIP(value),nodeIP(value),value);
 assert.equal(browser.canonicalIP('2001:0DB8:0:0:0:0:0:1'),'2001:db8::1');
});
test('browser parser reports bad records and enforces input event bounds',()=>{
 const invalid='{"timestamp":"2026-02-30T00:00:00Z","event":"LOGIN_FAILED","ip":"192.0.2.10"}\n{broken}\n';
 assert.equal(browser.parseText(invalid).errorCount,2);
 assert.throws(()=>browser.parseText(fixture,{maxEvents:2}),/exceeds/);
 assert.throws(()=>browser.analyze([],{threshold:1}),/threshold/);
});
