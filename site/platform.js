// Browser compatibility for the demonstrated input formats. The CLI retains Node's validators.
export function isIP(value) {
 if(typeof value!=='string')return 0;
 const v4=value.split('.');
 if(v4.length===4&&v4.every(x=>/^(0|[1-9][0-9]{0,2})$/.test(x)&&Number(x)<=255))return 4;
 if(!value.includes(':')||!/^[0-9a-fA-F:.]+$/.test(value))return 0;
 try {const u=new URL(`http://[${value}]/`);return u.hostname.startsWith('[')?6:0;}catch{return 0;}
}
// All replay fixtures carry explicit IDs; missing IDs are rejected in the browser adapter.
export function createHash(){throw new Error('Browser replay requires an explicit event ID');}
