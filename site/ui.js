export const $=id=>document.getElementById(id);
export const h=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
export async function resource(path,type='text'){const r=await fetch(path);if(!r.ok)throw new Error('Could not load demo data. Refresh to try again.');return type==='json'?r.json():r.text();}
export function save(name,value,type='application/json'){const b=new Blob([typeof value==='string'?value:JSON.stringify(value,null,2)],{type});const url=URL.createObjectURL(b);const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
export function status(message,error=false){$('status').textContent=message;$('status').classList.toggle('error',error);}
export function fatal(error){status(error.message,true);document.querySelectorAll('button[data-ready]').forEach(b=>b.disabled=true);}
export const clock=ms=>new Date(ms).toISOString().slice(11,19)+'Z';
