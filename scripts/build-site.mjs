import {readFile,writeFile,mkdir,cp} from 'node:fs/promises';
const root=new URL('../',import.meta.url);
export async function buildSite(){
 const out=new URL('_site/',root);await mkdir(out,{recursive:true});
 await cp(new URL('site/',root),out,{recursive:true});
 const cfg=JSON.parse(await readFile(new URL('site-config.json',root),'utf8'));
 let source=await readFile(new URL(cfg.engine,root),'utf8');
 source=source.replace(/from ['"]node:net['"]/g,"from './platform.js'").replace(/from ['"]node:crypto['"]/g,"from './platform.js'");
 if(/from ['"]node:/.test(source))throw new Error('Browser engine contains an unsupported Node import');
 await writeFile(new URL('engine.js',out),source);
 for(const [src,dest] of cfg.data)await cp(new URL(src,root),new URL(dest,out));
 await writeFile(new URL('.nojekyll',out),'');
}
if(process.argv[1]&&import.meta.url===(await import('node:url')).pathToFileURL(process.argv[1]).href){await buildSite();console.log('Browser demo built in _site/');}
