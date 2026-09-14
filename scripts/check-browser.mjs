import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve,sep,extname,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const pkg=JSON.parse(await readFile(resolve(root,'package.json'),'utf8'));
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const {buildSite}=await import('./build-site.mjs');
let server,browser;const checks=[],errors=[],requests=[];
const mime={'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml','.jsonl':'text/plain'};
async function downloadJSON(page,button){const [download]=await Promise.all([page.waitForEvent('download'),button.click()]);const stream=await download.createReadStream();let data='';for await(const chunk of stream)data+=chunk;return JSON.parse(data);}
async function isText(page,selector,text,label){await page.waitForFunction(({selector,text})=>document.querySelector(selector)?.textContent.trim()===text,{selector,text});assert.equal((await page.locator(selector).textContent()).trim(),text);checks.push(label??`${selector} = ${text}`);}
try{
 await buildSite();let base=process.env.DEMO_URL;
 if(!base){
  const dir=resolve(root,'_site');
  server=createServer(async(req,res)=>{try{let name=decodeURIComponent(new URL(req.url,'http://localhost').pathname);if(name.endsWith('/'))name+='index.html';const file=resolve(dir,'.'+name);if(!file.startsWith(dir+sep)){res.writeHead(403).end();return;}const content=await readFile(file);res.writeHead(200,{'Content-Type':mime[extname(file)]||'text/plain'});res.end(content);}catch{res.writeHead(404).end('Not found');}});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));base=`http://127.0.0.1:${server.address().port}/`;
 }
 browser=await chromium.launch({headless:true,...(process.env.BROWSER_EXECUTABLE?{executablePath:process.env.BROWSER_EXECUTABLE}:{})});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.setDefaultTimeout(12000);
 page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
 page.on('request',r=>requests.push({url:r.url(),method:r.method()}));
 await page.goto(base,{waitUntil:'networkidle'});

  await isText(page,'#events','15');await isText(page,'#alerts-count','2');
  await page.locator('#threshold').fill('6');assert.equal(await page.locator('#export-json').isDisabled(),true);checks.push('Editing inputs invalidates stale exports');
  await page.getByRole('button',{name:'Analyze logs',exact:true}).click();await isText(page,'#alerts-count','0');
  await page.locator('#reset').click();await page.locator('#allowlist').fill('192.0.2.10');await page.getByRole('button',{name:'Analyze logs',exact:true}).click();await isText(page,'#alerts-count','0');await isText(page,'#events','15');
  await page.locator('#reset').click();await page.locator('#scenario').selectOption('quiet');await page.locator('#load-sample').click();await isText(page,'#events','5');await isText(page,'#alerts-count','0');
  await page.locator('#window').fill('1800');await page.getByRole('button',{name:'Analyze logs',exact:true}).click();await isText(page,'#alerts-count','1');
  await page.locator('#scenario').selectOption('invalid');await page.locator('#load-sample').click();await isText(page,'#events','0');assert.match(await page.locator('#parse-summary').innerText(),/3 rejected/);checks.push('Malformed records are rejected visibly');
  await page.locator('#log-input').fill('');await page.getByRole('button',{name:'Analyze logs',exact:true}).click();assert.match(await page.locator('#status').innerText(),/paste log records/);assert.equal(await page.locator('#export-json').isDisabled(),true);checks.push('Empty input shows an actionable error');
  await page.locator('#file-input').setInputFiles({name:'sample.log',mimeType:'text/plain',buffer:Buffer.from('2026-08-01 12:00:00 LOGIN_FAILED 192.0.2.10\n2026-08-01 12:00:10 LOGIN_FAILED 192.0.2.10\n')});await isText(page,'#events','2');checks.push('Local log file input is analyzed');
  await page.locator('#file-input').setInputFiles({name:'large.log',mimeType:'text/plain',buffer:Buffer.alloc(1048577,65)});assert.match(await page.locator('#status').innerText(),/smaller than 1 MiB/);checks.push('Oversized file is rejected');
  await page.locator('#reset').click();const data=await downloadJSON(page,page.locator('#export-json'));assert.equal(data.alerts.length,2);checks.push('JSON export contains the analyzed alerts');
  const [csv]=await Promise.all([page.waitForEvent('download'),page.locator('#export-csv').click()]);let csvText='';for await(const c of await csv.createReadStream())csvText+=c;assert.match(csvText,/failure_burst/);checks.push('CSV export contains detection results');
  const fixture=await page.locator('#log-input').inputValue();await page.locator('#log-input').fill(fixture.replaceAll('lab_alex','<img src=x onerror=alert(1)>'));await page.getByRole('button',{name:'Analyze logs',exact:true}).click();await page.locator('#alerts details').first().locator('summary').click();assert.equal(await page.locator('#alerts img').count(),0);checks.push('Untrusted evidence is rendered as text');await page.locator('#reset').click();

 await page.evaluate(()=>{window.scrollTo(0,0);document.activeElement?.blur();const input=document.getElementById('log-input');if(input)input.scrollTop=0;});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);checks.push('Desktop layout fits viewport');
 if(process.env.CAPTURE_DIR){await mkdir(process.env.CAPTURE_DIR,{recursive:true});await page.screenshot({path:resolve(process.env.CAPTURE_DIR,'desktop.png'),fullPage:true});}
 await page.setViewportSize({width:390,height:844});await page.evaluate(()=>window.scrollTo(0,0));await page.waitForTimeout(150);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);checks.push('Phone layout fits viewport');
 assert.equal(await page.locator('nav a').count(),3);checks.push('Links connect all three project demos');
 if(process.env.CAPTURE_DIR)await page.screenshot({path:resolve(process.env.CAPTURE_DIR,'mobile.png'),fullPage:true});
 assert.deepEqual(errors,[],'Browser errors');assert.equal(requests.some(r=>r.method!=='GET'),false,'Input must not be uploaded');checks.push('No browser errors or input upload requests');
 const result={project:pkg.name,url:process.env.DEMO_URL||'Local static preview',checkedAt:new Date().toISOString(),checks,passed:checks.length};
 if(process.env.CAPTURE_DIR)await writeFile(resolve(process.env.CAPTURE_DIR,'results.json'),JSON.stringify(result,null,2));
 console.log(JSON.stringify(result,null,2));
}finally{if(browser)await browser.close();if(server)await new Promise(r=>server.close(r));}
