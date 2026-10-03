// ---------- Green API — отправка WhatsApp-сообщений клиентам арендатора ----------
// Все запросы уходят ОТСЮДА, с сервера (а не из браузера пользователя), используя
// idInstance/apiTokenInstance/apiUrl/mediaUrl, которые сам пользователь сохраняет в
// настройках приложения (settings.whatsapp) — они приходят на сервер как обычное поле
// внутри payload.settings через уже существующий /api/sync и хранятся в users.payload.
//
// Базовые хосты: у каждого инстанса Green API есть СВОЙ apiUrl/mediaUrl (см. личный
// кабинет console.greenapi.com) — использовать их надёжнее. Если пользователь их не
// указал, используем универсальные хосты api.greenapi.com/media.greenapi.com (работают,
// но без гарантии минимального времени ответа — см. рекомендации Green API).
const DEFAULT_API_URL='https://api.greenapi.com';
const DEFAULT_MEDIA_URL='https://media.greenapi.com';

// российские номера, сохранённые с ведущей "8", для WhatsApp нужно привести к "7"
// (тот же приём, что и в user/index.html — waPhoneDigits)
function waDigits(phone){
 let d=String(phone||'').replace(/\D/g,'');
 if(d.length===11&&d[0]==='8') d='7'+d.slice(1);
 return d;
}
function waChatId(phone){
 const d=waDigits(phone);
 return d?`${d}@c.us`:null;
}
function cleanHost(url){
 return String(url||'').trim().replace(/\/+$/,'');
}
function apiBase(cfg){
 return cleanHost(cfg.apiUrl)||DEFAULT_API_URL;
}
function mediaBase(cfg){
 return cleanHost(cfg.mediaUrl)||DEFAULT_MEDIA_URL;
}
async function parseJsonSafe(resp){
 try{ return await resp.json(); }catch(e){ return {}; }
}
async function greenApiGetState(cfg){
 const url=`${apiBase(cfg)}/waInstance${cfg.idInstance}/getStateInstance/${cfg.apiTokenInstance}`;
 const r=await fetch(url,{method:'GET'});
 const data=await parseJsonSafe(r);
 if(!r.ok) throw Object.assign(new Error(data.message||('HTTP '+r.status)),{status:r.status});
 return data;
}
async function greenApiSendMessage(cfg){
 const chatId=waChatId(cfg.phone);
 if(!chatId) throw new Error('У клиента не указан телефон для WhatsApp');
 const url=`${apiBase(cfg)}/waInstance${cfg.idInstance}/sendMessage/${cfg.apiTokenInstance}`;
 const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chatId,message:cfg.message||''})});
 const data=await parseJsonSafe(r);
 if(!r.ok) throw Object.assign(new Error(data.message||('HTTP '+r.status)),{status:r.status});
 return data;
}
async function greenApiSendFile(cfg){
 const chatId=waChatId(cfg.phone);
 if(!chatId) throw new Error('У клиента не указан телефон для WhatsApp');
 const url=`${mediaBase(cfg)}/waInstance${cfg.idInstance}/sendFileByUpload/${cfg.apiTokenInstance}`;
 const form=new FormData();
 form.append('chatId',chatId);
 if(cfg.caption) form.append('caption',String(cfg.caption).slice(0,1024));
 form.append('file',new Blob([cfg.buffer],{type:cfg.mime||'application/octet-stream'}),cfg.fileName||'file');
 const r=await fetch(url,{method:'POST',body:form});
 const data=await parseJsonSafe(r);
 if(!r.ok) throw Object.assign(new Error(data.message||('HTTP '+r.status)),{status:r.status});
 return data;
}
// "data:image/jpeg;base64,...." -> {mime,buffer}
function parseDataUrl(dataUrl){
 const m=/^data:([^;,]+)(;base64)?,(.+)$/.exec(String(dataUrl||''));
 if(!m) return null;
 const mime=m[1]||'application/octet-stream';
 const isBase64=!!m[2];
 const raw=m[3];
 try{
  const buffer=isBase64?Buffer.from(raw,'base64'):Buffer.from(decodeURIComponent(raw),'utf8');
  return {mime,buffer};
 }catch(e){ return null; }
}
module.exports={waDigits,waChatId,greenApiGetState,greenApiSendMessage,greenApiSendFile,parseDataUrl,DEFAULT_API_URL,DEFAULT_MEDIA_URL};
