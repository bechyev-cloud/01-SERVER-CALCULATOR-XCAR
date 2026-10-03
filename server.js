const express=require('express');
const cors=require('cors');
const Database=require('better-sqlite3');
const bcrypt=require('bcryptjs');
const crypto=require('crypto');
const path=require('path');
const fs=require('fs');
const config=require('./config');
// собственная реализация Web Push (RFC 8291/8292) на встроенном crypto — без npm-пакета
// web-push, чтобы сервер по-прежнему разворачивался без единой внешней зависимости
const webpush=require('./webpush');
// WhatsApp-уведомления клиентам через Green API — см. whatsapp.js. Данные для подключения
// (idInstance/apiTokenInstance) приходят как обычное поле settings.whatsapp внутри
// payload через уже существующий /api/sync и хранятся вместе со всем остальным payload
// пользователя — отдельной таблицы под учётные данные заводить не нужно.
const whatsapp=require('./whatsapp');

const app=express();
app.use(cors());
app.use(express.json({limit:'25mb'}));

const PORT=Number(process.env.PORT||config.port||3000);
const DB_FILE=process.env.DB_FILE||path.resolve(__dirname,config.dbFile||'xcar.sqlite');
const BACKUP_DIR=process.env.BACKUP_DIR||path.resolve(__dirname,config.backupDir||'backups');
fs.mkdirSync(BACKUP_DIR,{recursive:true});

const db=new Database(DB_FILE);
db.pragma('journal_mode=WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY,value TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, email TEXT DEFAULT '', phone TEXT DEFAULT '',
 subscription_until INTEGER NOT NULL, blocked INTEGER DEFAULT 0,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, payload TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER,created_at INTEGER);
CREATE TABLE IF NOT EXISTS subscription_requests(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,username TEXT,name TEXT,phone TEXT,
 months INTEGER,price INTEGER,status TEXT DEFAULT 'pending',created_at INTEGER,decided_at INTEGER
);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,from_admin INTEGER,message TEXT,file_name TEXT DEFAULT '',file_type TEXT DEFAULT '',file_data TEXT DEFAULT '',created_at INTEGER
);
CREATE TABLE IF NOT EXISTS broadcasts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,message TEXT,target TEXT DEFAULT 'all',
 target_user_ids TEXT DEFAULT '',created_at INTEGER,expires_at INTEGER,active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS settings_restore_jobs(
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,settings_json TEXT NOT NULL DEFAULT '{}',restore_text TEXT DEFAULT '',created_at INTEGER NOT NULL,applied_at INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS blacklist_files(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, mime TEXT DEFAULT 'text/plain', data TEXT NOT NULL DEFAULT '', size INTEGER DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS push_subscriptions(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, endpoint TEXT UNIQUE NOT NULL,
 p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
-- дедупликация "напоминаний о следующей оплате" через WhatsApp: один автомобиль в активной
-- аренде получает не более одного напоминания за календарный день аренды. car_key включает
-- rentedSince, поэтому у каждой новой аренды той же машины счётчик дней начинается заново.
CREATE TABLE IF NOT EXISTS whatsapp_reminder_log(
 user_id INTEGER NOT NULL, car_key TEXT NOT NULL, last_day_index INTEGER NOT NULL DEFAULT 0,
 sent_at INTEGER NOT NULL, PRIMARY KEY(user_id,car_key)
);
`);
for(const stmt of [
 "ALTER TABLE messages ADD COLUMN file_name TEXT DEFAULT ''",
 "ALTER TABLE messages ADD COLUMN file_type TEXT DEFAULT ''",
 "ALTER TABLE messages ADD COLUMN file_data TEXT DEFAULT ''"
]){try{db.exec(stmt)}catch(e){if(!String(e.message).includes('duplicate column')) throw e}}

const q={
 userByName:db.prepare('SELECT * FROM users WHERE username=?'),
 userById:db.prepare('SELECT * FROM users WHERE id=?')
};
const now=()=>Date.now();
const hash=p=>bcrypt.hashSync(String(p),12);
const okPass=(p,h)=>bcrypt.compareSync(String(p),h);
const token=()=>crypto.randomBytes(32).toString('hex');
const setting=(key,fallback='')=>{
 const r=db.prepare('SELECT value FROM app_settings WHERE key=?').get(key);
 return r?.value!==undefined?r.value:fallback;
};
const setSetting=(key,value)=>{
 db.prepare('INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,String(value));
};
const adminUser=process.env.ADMIN_USER||config.adminUser||'admin';
const adminPass=process.env.ADMIN_PASSWORD||config.adminPassword||'CHANGE_ME_NOW';

function userAuth(req){
 const h=req.headers.authorization||'';
 if(h.startsWith('Bearer ')){
  const s=db.prepare('SELECT * FROM sessions WHERE token=?').get(h.slice(7));
  if(s)return q.userById.get(s.user_id);
 }
 const b=req.body||{};
 if(b.username&&b.password){
  const u=q.userByName.get(b.username);
  if(u&&okPass(b.password,u.password_hash))return u;
 }
 return null;
}
function adminAuth(req){
 const h=req.headers.authorization||'';
 return h.startsWith('Basic ') &&
   Buffer.from(h.slice(6),'base64').toString()===`${adminUser}:${adminPass}`;
}
function publicSubscription(){
 const monthPrice=Number(setting('month_price',process.env.MONTH_PRICE||config.monthPrice||500));
 return {
  monthPrice,
  discounts:{
   1:Number(setting('discount_1',0)),
   3:Number(setting('discount_3',10)),
   6:Number(setting('discount_6',15)),
   12:Number(setting('discount_12',20))
  },
  bank:setting('pay_bank',process.env.PAY_BANK||config.payBank||'Сбербанк'),
  cardNumber:setting('pay_card',process.env.PAY_CARD||config.payCard||''),
  recipient:setting('pay_recipient',process.env.PAY_RECIPIENT||config.payRecipient||''),
  phone:setting('pay_phone',process.env.PAY_PHONE||config.payPhone||''),
  qrText:setting('pay_qr_text',''),
  qrMode:setting('pay_qr_mode','text'),
  qrImage:setting('pay_qr_image',''),
  instruction:setting('pay_instruction','После оплаты нажмите «Я оплатил — отправить заявку».')
 };
}
function subscriptionPrice(months){
 const p=publicSubscription(), m=Number(months);
 const discount=Number(p.discounts[m]||0);
 return Math.round(p.monthPrice*m*(1-discount/100));
}
function backupSnapshot(){
 const stamp=new Date().toISOString().replace(/[:.]/g,'-');
 const dbOut=path.join(BACKUP_DIR,`xcar-${stamp}.sqlite`);
 const jsonOut=path.join(BACKUP_DIR,`xcar-${stamp}.json`);
 db.pragma('wal_checkpoint(TRUNCATE)');
 fs.copyFileSync(DB_FILE,dbOut);
 const snapshot={
  createdAt:now(),
  users:db.prepare('SELECT id,username,password_hash,email,phone,subscription_until,blocked,created_at,updated_at,payload FROM users').all(),
  subscriptionRequests:db.prepare('SELECT * FROM subscription_requests').all(),
  messages:db.prepare('SELECT * FROM messages').all(),
  broadcasts:db.prepare('SELECT * FROM broadcasts').all(),
  settingsRestoreJobs:db.prepare('SELECT * FROM settings_restore_jobs').all(),
  settings:db.prepare('SELECT * FROM app_settings').all()
 };
 fs.writeFileSync(jsonOut,JSON.stringify(snapshot,null,2),'utf8');
 return {stamp,dbFile:dbOut,jsonFile:jsonOut};
}
function cleanupBackups(){
 const files=fs.readdirSync(BACKUP_DIR).filter(f=>f.endsWith('.sqlite')||f.endsWith('.json'));
 const max=Number(process.env.BACKUP_RETENTION||config.backupRetention||30)*2;
 if(files.length>max){
  files.sort();
  for(const f of files.slice(0,files.length-max)){try{fs.unlinkSync(path.join(BACKUP_DIR,f))}catch{}}
 }
}
function dailyBackup(){
 try{backupSnapshot();cleanupBackups();console.log('XCAR daily backup created');}
 catch(e){console.error('backup error',e.message);}
}
function scheduleDailyBackup(){
 const d=new Date(); const next=new Date(d);
 next.setHours(3,0,0,0);
 if(next<=d)next.setDate(next.getDate()+1);
 const delay=next-d;
 setTimeout(()=>{dailyBackup();setInterval(dailyBackup,24*60*60*1000)},delay);
 console.log('XCAR daily backup scheduled for '+next.toLocaleString('ru-RU'));
}
scheduleDailyBackup();

app.get('/health',(req,res)=>res.json({ok:true,time:now(),server:'XCAR'}));

// ---------- Web Push (RFC 8291/8292), см. webpush.js — свой VAPID-ключ сервера
// генерируется один раз и хранится в app_settings; на нём завязана подпись всех
// push-уведомлений (и адресных "на другом устройстве", и рассылок администратора) ----------
function getVapidKeys(){
 let publicKey=setting('vapid_public_key',''), privateKey=setting('vapid_private_key','');
 if(!publicKey||!privateKey){
  const k=webpush.generateVapidKeys();
  publicKey=k.publicKey; privateKey=k.privateKey;
  setSetting('vapid_public_key',publicKey);
  setSetting('vapid_private_key',privateKey);
 }
 return {publicKey,privateKey};
}
const VAPID_SUBJECT=process.env.VAPID_SUBJECT||config.vapidSubject||'mailto:admin@xcar.local';
// отправляет push на список подписок (строки таблицы push_subscriptions), удаляя из базы
// те, что браузер/push-сервис считает более не существующими (404/410 — отписка/удаление)
async function sendPushToSubscriptions(rows,payload){
 const vapid=getVapidKeys();
 let sent=0;
 await Promise.all(rows.map(async(row)=>{
  try{
   const result=await webpush.sendWebPush({
    subscription:{endpoint:row.endpoint,keys:{p256dh:row.p256dh,auth:row.auth}},
    payload,vapid,subject:VAPID_SUBJECT
   });
   if(result.ok) sent++;
   else if(result.gone) db.prepare('DELETE FROM push_subscriptions WHERE id=?').run(row.id);
  }catch(e){/* временная сетевая ошибка — оставляем подписку, попробуем в другой раз */}
 }));
 return sent;
}
// подбирает push-подписки под аудиторию рассылки администратора (та же логика таргетинга,
// что и у /api/public/broadcasts/for-user) и отправляет им push
async function broadcastPush(target,selectedIds,payload){
 let rows;
 if(target==='all'){
  rows=db.prepare('SELECT * FROM push_subscriptions').all();
 }else if(target==='selected'){
  const ids=(selectedIds||[]).map(Number).filter(Boolean);
  if(!ids.length) return 0;
  rows=db.prepare(`SELECT * FROM push_subscriptions WHERE user_id IN (${ids.map(()=>'?').join(',')})`).all(...ids);
 }else{
  const t=now();
  let matchIds;
  if(target==='active') matchIds=db.prepare('SELECT id FROM users WHERE blocked=0 AND subscription_until>?').all(t).map(x=>x.id);
  else if(target==='expired') matchIds=db.prepare('SELECT id FROM users WHERE subscription_until<=?').all(t).map(x=>x.id);
  else if(target==='blocked') matchIds=db.prepare('SELECT id FROM users WHERE blocked=1').all().map(x=>x.id);
  else matchIds=[];
  if(!matchIds.length) return 0;
  rows=db.prepare(`SELECT * FROM push_subscriptions WHERE user_id IN (${matchIds.map(()=>'?').join(',')})`).all(...matchIds);
 }
 if(!rows.length) return 0;
 return sendPushToSubscriptions(rows,payload);
}
app.get('/api/push/vapid-public-key',(req,res)=>{
 res.json({ok:true,enabled:true,publicKey:getVapidKeys().publicKey});
});
app.post('/api/push/subscribe',(req,res)=>{
 const sub=req.body&&req.body.subscription;
 if(!sub||!sub.endpoint||!sub.keys||!sub.keys.p256dh||!sub.keys.auth)
  return res.status(400).json({ok:false,error:'Некорректная push-подписка'});
 // привязка к аккаунту нужна только для адресной рассылки/уведомлений "на другом устройстве";
 // если логина/пароля нет (или они неверны) — подписка всё равно сохраняется как анонимная
 // и продолжает получать общие рассылки администратора (target:"all")
 const u=userAuth(req);
 const t=now();
 db.prepare(`INSERT INTO push_subscriptions(user_id,endpoint,p256dh,auth,created_at,updated_at) VALUES(?,?,?,?,?,?)
   ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,p256dh=excluded.p256dh,auth=excluded.auth,updated_at=excluded.updated_at`)
  .run(u?u.id:null,sub.endpoint,sub.keys.p256dh,sub.keys.auth,t,t);
 res.json({ok:true,enabled:true});
});
app.post('/api/push/unsubscribe',(req,res)=>{
 const endpoint=String(req.body?.endpoint||'');
 if(endpoint) db.prepare('DELETE FROM push_subscriptions WHERE endpoint=?').run(endpoint);
 res.json({ok:true,enabled:true});
});
// уведомляет ДРУГИЕ устройства с тем же аккаунтом (кроме excludeEndpoint — обычно своё
// собственное устройство) о действии: машина оформлена/возвращена и т.п.
app.post('/api/push/notify',async(req,res)=>{
 const u=userAuth(req);
 if(!u) return res.status(401).json({ok:false,error:'auth'});
 const title=String(req.body?.title||'XCAR').trim()||'XCAR';
 const body=String(req.body?.body||'').trim();
 const excludeEndpoint=String(req.body?.excludeEndpoint||'');
 if(!body) return res.json({ok:true,enabled:true,delivered:0,sent:0});
 const rows=db.prepare('SELECT * FROM push_subscriptions WHERE user_id=? AND endpoint<>?').all(u.id,excludeEndpoint);
 const sent=await sendPushToSubscriptions(rows,{title,body});
 res.json({ok:true,enabled:true,delivered:rows.length,sent});
});


app.get('/api/public/config',(req,res)=>{
 const url=setting('client_server_url',process.env.CLIENT_SERVER_URL||config.clientServerUrl||'https://zero1-server-calculator-xcar.onrender.com');
 res.json({ok:true,clientServerUrl:url});
});

app.get('/api/public/subscription',(req,res)=>res.json(publicSubscription()));

app.get('/api/public/broadcasts',(req,res)=>{
 // Без авторизации доступны только общие сообщения. Адресные рассылки
 // выдаются только через /for-user после проверки аккаунта.
 const t=now();
 const all=db.prepare(`SELECT * FROM broadcasts WHERE active=1 AND target='all' AND (expires_at=0 OR expires_at>?) ORDER BY id DESC LIMIT 10`).all(t);
 res.json({broadcasts:all.map(x=>({id:x.id,title:x.title,message:x.message,created_at:x.created_at,expires_at:x.expires_at,target:x.target}))});
});

// GET — только если клиент передаёт Bearer-токен сессии; POST — тот же обработчик, но
// позволяет авторизоваться логином/паролем в теле запроса (userAuth поддерживает оба
// способа), т.к. само приложение пользователя токены сессий нигде не хранит и не использует
function handleBroadcastsForUser(req,res){
 const u=userAuth(req); if(!u)return res.status(401).json({error:'auth'});
 const t=now();
 const rows=db.prepare(`SELECT * FROM broadcasts WHERE active=1 AND (expires_at=0 OR expires_at>?) ORDER BY id DESC LIMIT 20`).all(t);
 const filtered=rows.filter(x=>{
  if(x.target==='all')return true;
  if(x.target==='active')return !u.blocked && u.subscription_until>t;
  if(x.target==='expired')return u.subscription_until<=t;
  if(x.target==='blocked')return !!u.blocked;
  if(x.target==='selected'){try{return JSON.parse(x.target_user_ids||'[]').map(Number).includes(Number(u.id))}catch{return false}}
  return false;
 });
 res.json({broadcasts:filtered.map(x=>({id:x.id,title:x.title,message:x.message,created_at:x.created_at,expires_at:x.expires_at}))});
}
app.get('/api/public/broadcasts/for-user',handleBroadcastsForUser);
app.post('/api/public/broadcasts/for-user',handleBroadcastsForUser);

app.post('/api/register',(req,res)=>{
 const {username,password,email='',phone='',payload={}}=req.body||{};
 if(!username||!password)return res.status(400).json({error:'Логин и пароль обязательны'});
 if(q.userByName.get(username))return res.status(409).json({error:'Такой логин уже существует'});
 const t=now(),trial=Math.max(0,Number(setting('trial_days',30)));
 const until=t+trial*86400000;
 const info=db.prepare('INSERT INTO users(username,password_hash,email,phone,subscription_until,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?,?)')
  .run(username,hash(password),email,phone,until,t,t,JSON.stringify(payload||{}));
 const tok=token();db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(tok,info.lastInsertRowid,t);
 res.json({ok:true,token:tok,subscriptionUntil:until,updatedAt:t});
});

app.post('/api/login',(req,res)=>{
 const {username,password}=req.body||{},u=q.userByName.get(username);
 if(!u)return res.status(404).json({error:'Аккаунт не найден'});
 if(!okPass(password,u.password_hash))return res.status(401).json({error:'Неверный пароль'});
 if(u.blocked)return res.status(403).json({error:'Пользователь заблокирован'});
 const tok=token();db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(tok,u.id,now());
 let payload={};try{payload=JSON.parse(u.payload||'{}')}catch{}
 res.json({ok:true,token:tok,email:u.email,phone:u.phone,subscriptionUntil:u.subscription_until,updatedAt:u.updated_at,payload});
});

app.post('/api/sync',(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 if(u.blocked)return res.status(403).json({error:'blocked'});
 const payload=req.body.payload||{},t=now();
 db.prepare('UPDATE users SET payload=?,updated_at=? WHERE id=?').run(JSON.stringify(payload),t,u.id);
 const restoreJob=db.prepare('SELECT id,settings_json,restore_text,created_at FROM settings_restore_jobs WHERE user_id=? AND applied_at=0 ORDER BY id DESC LIMIT 1').get(u.id);
 let settingsRestore=null;
 if(restoreJob){let rs={};try{rs=JSON.parse(restoreJob.settings_json||'{}')}catch{} settingsRestore={id:restoreJob.id,text:restoreJob.restore_text||'',settings:rs,created_at:restoreJob.created_at};}
 res.json({ok:true,updatedAt:t,subscriptionUntil:u.subscription_until,payload,settingsRestore});
});

app.post('/api/settings-restore/ack',(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 const id=Number(req.body?.id||0);
 if(!id)return res.status(400).json({error:'id required'});
 db.prepare('UPDATE settings_restore_jobs SET applied_at=? WHERE id=? AND user_id=? AND applied_at=0').run(now(),id,u.id);
 res.json({ok:true});
});

// ---------- WhatsApp-уведомления клиентам (Green API) ----------
// Конфигурация (idInstance/apiTokenInstance/apiUrl/mediaUrl и переключатели событий)
// читается прямо из последнего синхронизированного payload пользователя — отдельно
// её сохранять не нужно, она уже приезжает с каждым /api/sync как payload.settings.whatsapp.
function userPayloadOf(u){
 try{ return JSON.parse(u.payload||'{}'); }catch(e){ return {}; }
}
function whatsappConfigOf(u){
 const payload=userPayloadOf(u);
 const w=(payload.settings&&typeof payload.settings==='object'&&payload.settings.whatsapp)||{};
 return {
  enabled:!!w.enabled,
  idInstance:String(w.idInstance||'').trim(),
  apiTokenInstance:String(w.apiTokenInstance||'').trim(),
  apiUrl:String(w.apiUrl||'').trim(),
  mediaUrl:String(w.mediaUrl||'').trim(),
  notifyOnCreate:w.notifyOnCreate!==false,
  notifyOnComplete:w.notifyOnComplete!==false,
  notifyOnDebtReminder:w.notifyOnDebtReminder!==false,
  notifyOnDebtAdd:w.notifyOnDebtAdd!==false
 };
}
// Проверка связи с Green API ещё ДО сохранения настроек — пользователь вводит
// idInstance/apiTokenInstance (и, опционально, свои apiUrl/mediaUrl) и сразу видит,
// подключён ли инстанс, не отправляя тестовое сообщение.
app.post('/api/whatsapp/test',async(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 const {idInstance,apiTokenInstance,apiUrl,mediaUrl}=req.body||{};
 if(!idInstance||!apiTokenInstance) return res.status(400).json({ok:false,error:'Укажите idInstance и apiTokenInstance'});
 try{
  const data=await whatsapp.greenApiGetState({idInstance:String(idInstance).trim(),apiTokenInstance:String(apiTokenInstance).trim(),apiUrl,mediaUrl});
  res.json({ok:true,state:data.stateInstance||'unknown'});
 }catch(e){
  res.status(502).json({ok:false,error:e.message||'Не удалось связаться с Green API'});
 }
});
// Единая точка отправки события клиенту (оформление/завершение/оплата) — вызывается
// приложением сразу в момент действия, с уже готовым текстом сообщения и (опционально)
// вложением — картинкой/PDF в виде data:URL. Сама отправка всегда идёт с сервера, учётные
// данные Green API при этом остаются на сервере и не возвращаются клиенту.
app.post('/api/whatsapp/send',async(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 const {type,phone,message,attachmentDataUrl,attachmentName}=req.body||{};
 if(!phone) return res.status(400).json({ok:false,error:'Не указан телефон клиента'});
 const cfg=whatsappConfigOf(u);
 if(!cfg.enabled) return res.json({ok:false,skipped:'disabled'});
 if(!cfg.idInstance||!cfg.apiTokenInstance) return res.json({ok:false,skipped:'not_configured'});
 const eventAllowed=type==='create'?cfg.notifyOnCreate:type==='complete'?cfg.notifyOnComplete:type==='debt'?cfg.notifyOnDebtAdd:true;
 if(!eventAllowed) return res.json({ok:false,skipped:'event_disabled'});
 try{
  let result;
  if(attachmentDataUrl){
   const parsed=whatsapp.parseDataUrl(attachmentDataUrl);
   if(!parsed) return res.status(400).json({ok:false,error:'Повреждённое вложение'});
   result=await whatsapp.greenApiSendFile({idInstance:cfg.idInstance,apiTokenInstance:cfg.apiTokenInstance,apiUrl:cfg.apiUrl,mediaUrl:cfg.mediaUrl,phone,buffer:parsed.buffer,mime:parsed.mime,fileName:attachmentName||'file',caption:message||''});
  }else{
   result=await whatsapp.greenApiSendMessage({idInstance:cfg.idInstance,apiTokenInstance:cfg.apiTokenInstance,apiUrl:cfg.apiUrl,mediaUrl:cfg.mediaUrl,phone,message:message||''});
  }
  res.json({ok:true,result});
 }catch(e){
  res.status(502).json({ok:false,error:e.message||'Не удалось отправить сообщение'});
 }
});
// Фоновая проверка "напоминаний о следующей оплате": раз в интервал обходит ВСЕХ
// пользователей с включённым WhatsApp и активной арендой (cars[i].rented), и как только
// у машины наступает новый календарный день аренды (dayIndex = сколько полных суток
// прошло с cars[i].rentedSince) — шлёт клиенту одно напоминание на этот день. Срабатывает
// независимо от того, открыто ли сейчас приложение пользователя — именно поэтому это
// фоновая задача на сервере, а не в браузере (см. обсуждение при добавлении функции).
function checkWhatsappReminders(){
 let rows;
 try{ rows=db.prepare('SELECT id,payload FROM users WHERE blocked=0').all(); }
 catch(e){ console.error('whatsapp reminder scan failed',e.message); return; }
 rows.forEach(u=>{
  let payload; try{ payload=JSON.parse(u.payload||'{}'); }catch(e){ return; }
  const w=(payload.settings&&typeof payload.settings==='object'&&payload.settings.whatsapp)||{};
  if(!w.enabled||w.notifyOnDebtReminder===false||!w.idInstance||!w.apiTokenInstance) return;
  const cars=Array.isArray(payload.cars)?payload.cars:[];
  cars.forEach(c=>{
   if(!c||!c.rented||!c.rentedSince||!c.rentClientPhone) return;
   const start=new Date(c.rentedSince).getTime();
   if(!(start>0)) return;
   const dayIndex=Math.floor((Date.now()-start)/86400000);
   if(dayIndex<1) return; // новый день аренды ещё не наступил
   const carKey=String(c.name||'car')+'|'+c.rentedSince;
   const row=db.prepare('SELECT last_day_index FROM whatsapp_reminder_log WHERE user_id=? AND car_key=?').get(u.id,carKey);
   if(row&&row.last_day_index>=dayIndex) return;
   const priceText=c.price?`${Math.round(c.price)} ₽/сутки`:'по тарифу аренды';
   const message=`Добрый день! Наступил новый день аренды автомобиля «${c.name||''}». Пожалуйста, не забудьте произвести оплату за сутки (${priceText}).`;
   whatsapp.greenApiSendMessage({idInstance:String(w.idInstance),apiTokenInstance:String(w.apiTokenInstance),apiUrl:w.apiUrl,mediaUrl:w.mediaUrl,phone:c.rentClientPhone,message})
    .then(()=>{
     db.prepare('INSERT INTO whatsapp_reminder_log(user_id,car_key,last_day_index,sent_at) VALUES(?,?,?,?) ON CONFLICT(user_id,car_key) DO UPDATE SET last_day_index=excluded.last_day_index,sent_at=excluded.sent_at').run(u.id,carKey,dayIndex,now());
    })
    .catch(e=>console.error('whatsapp reminder send failed, user',u.id,e.message));
  });
 });
}
function scheduleWhatsappReminders(){
 const INTERVAL_MS=20*60*1000; // раз в 20 минут — новый день аренды не требует более частой проверки
 setTimeout(checkWhatsappReminders,15000);
 setInterval(checkWhatsappReminders,INTERVAL_MS);
}
scheduleWhatsappReminders();

app.post('/api/subscription/request',(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 const {name='',phone='',months=1,price}=req.body||{};
 const allowed=[1,3,6,12],m=Number(months);
 if(!allowed.includes(m))return res.status(400).json({error:'invalid months'});
 const finalPrice=Number.isFinite(Number(price))?Number(price):subscriptionPrice(m);
 const info=db.prepare('INSERT INTO subscription_requests(user_id,username,name,phone,months,price,created_at) VALUES(?,?,?,?,?,?,?)')
  .run(u.id,u.username,name,phone,m,finalPrice,now());
 res.json({ok:true,id:info.lastInsertRowid,price:finalPrice});
});

app.get('/api/account',(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 res.json({id:u.id,username:u.username,email:u.email,phone:u.phone,subscriptionUntil:u.subscription_until,blocked:!!u.blocked});
});

app.get('/api/messages',(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 res.json({messages:db.prepare('SELECT id,from_admin,message,file_name,file_type,file_data,created_at FROM messages WHERE user_id=? ORDER BY id').all(u.id)});
});
app.post('/api/messages',(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 const message=String(req.body?.message||'').trim(), file=req.body?.file||null;
 if(!message&&!file)return res.status(400).json({error:'message'});
 if(file?.data&&String(file.data).length>14*1024*1024)return res.status(413).json({error:'file too large'});
 db.prepare('INSERT INTO messages(user_id,from_admin,message,file_name,file_type,file_data,created_at) VALUES(?,?,?,?,?,?,?)').run(u.id,0,message,String(file?.name||''),String(file?.type||''),String(file?.data||''),now());
 res.json({ok:true});
});

app.get('/api/admin/config',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 res.json({
  clientServerUrl:setting('client_server_url',process.env.CLIENT_SERVER_URL||config.clientServerUrl||'https://zero1-server-calculator-xcar.onrender.com'),
  trialDays:Number(setting('trial_days',30)),
  ...publicSubscription()
 });
});
app.post('/api/admin/config',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const b=req.body||{},url=String(b.clientServerUrl||'').trim();
 if(url&&!/^https?:\/\//i.test(url))return res.status(400).json({error:'invalid url'});
 if(url)setSetting('client_server_url',url.replace(/\/+$/,''));
 for(const k of ['trialDays','monthPrice','discount_1','discount_3','discount_6','discount_12','pay_bank','pay_card','pay_recipient','pay_phone','pay_qr_text','pay_qr_mode','pay_qr_image','pay_instruction']){
  if(b[k]!==undefined){
   const map={trialDays:'trial_days',monthPrice:'month_price',discount_1:'discount_1',discount_3:'discount_3',discount_6:'discount_6',discount_12:'discount_12',pay_bank:'pay_bank',pay_card:'pay_card',pay_recipient:'pay_recipient',pay_phone:'pay_phone',pay_qr_text:'pay_qr_text',pay_qr_mode:'pay_qr_mode',pay_qr_image:'pay_qr_image',pay_instruction:'pay_instruction'};
   setSetting(map[k]||k,b[k]);
  }
 }
 res.json({ok:true,...publicSubscription(),clientServerUrl:setting('client_server_url')});
});

app.post('/api/admin/apply-trial-all',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const days=Math.max(0,Number(req.body?.days ?? setting('trial_days',30)));
 setSetting('trial_days',days);
 const until=now()+days*86400000;
 db.prepare('UPDATE users SET subscription_until=?,updated_at=?').run(until,now());
 res.json({ok:true,days,subscriptionUntil:until});
});

app.get('/api/admin/users',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const users=db.prepare('SELECT id,username,email,phone,subscription_until,blocked,created_at,updated_at,payload FROM users ORDER BY id DESC').all();
 res.json({users});
});
app.get('/api/admin/users/:id',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const u=q.userById.get(req.params.id);if(!u)return res.status(404).json({error:'not found'});
 let payload={};try{payload=JSON.parse(u.payload||'{}')}catch{}
 res.json({...u,password_hash:undefined,payload});
});

app.get('/api/admin/requests',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 res.json({requests:db.prepare('SELECT * FROM subscription_requests ORDER BY id DESC').all()});
});

app.post('/api/admin/users/:id/subscription',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const u=q.userById.get(req.params.id);if(!u)return res.status(404).json({error:'not found'});
 const b=req.body||{},mode=b.mode||'add';
 let until;
 if(mode==='set'){until=now()+Math.max(0,Number(b.days||0))*86400000;}
 else if(mode==='remove'){until=0;}
 else {until=Math.max(now(),u.subscription_until)+Number(b.days||0)*86400000;}
 db.prepare('UPDATE users SET subscription_until=?,updated_at=? WHERE id=?').run(until,now(),u.id);
 res.json({ok:true,subscriptionUntil:until});
});

app.post('/api/admin/requests/:id/decision',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const r=db.prepare('SELECT * FROM subscription_requests WHERE id=?').get(req.params.id);
 if(!r)return res.status(404).json({error:'not found'});
 const status=req.body.status==='approved'?'approved':'rejected';
 db.prepare('UPDATE subscription_requests SET status=?,decided_at=? WHERE id=?').run(status,now(),r.id);
 if(status==='approved'){
  const u=q.userById.get(r.user_id);
  if(u){
   const until=Math.max(now(),u.subscription_until)+r.months*30*86400000;
   db.prepare('UPDATE users SET subscription_until=?,updated_at=? WHERE id=?').run(until,now(),u.id);
  }
 }
 res.json({ok:true});
});

app.post('/api/admin/users/:id/block',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 db.prepare('UPDATE users SET blocked=?,updated_at=? WHERE id=?').run(req.body?.blocked?1:0,now(),req.params.id);
 res.json({ok:true});
});
app.delete('/api/admin/users/:id',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 db.prepare('DELETE FROM sessions WHERE user_id=?').run(req.params.id);
 db.prepare('DELETE FROM messages WHERE user_id=?').run(req.params.id);
 db.prepare('DELETE FROM subscription_requests WHERE user_id=?').run(req.params.id);
 db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
 res.json({ok:true});
});

app.post('/api/admin/message',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const {userId,message}=req.body||{}, file=req.body?.file||null;
 if(!userId||(!String(message||'').trim()&&!file))return res.status(400).json({error:'message'});
 if(file?.data&&String(file.data).length>14*1024*1024)return res.status(413).json({error:'file too large'});
 db.prepare('INSERT INTO messages(user_id,from_admin,message,file_name,file_type,file_data,created_at) VALUES(?,?,?,?,?,?,?)').run(userId,1,String(message||'').trim(),String(file?.name||''),String(file?.type||''),String(file?.data||''),now());
 res.json({ok:true});
});
app.post('/api/admin/message-bulk',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const {userIds=[],target='all',message=''}=req.body||{}, file=req.body?.file||null;
 let ids=Array.isArray(userIds)?userIds.map(Number).filter(Boolean):[];
 if(!ids.length){const t=now(); if(target==='active')ids=db.prepare('SELECT id FROM users WHERE blocked=0 AND subscription_until>?').all(t).map(x=>x.id); else if(target==='expired')ids=db.prepare('SELECT id FROM users WHERE subscription_until<=?').all(t).map(x=>x.id); else if(target==='blocked')ids=db.prepare('SELECT id FROM users WHERE blocked=1').all().map(x=>x.id); else ids=db.prepare('SELECT id FROM users').all().map(x=>x.id);}
 if(!ids.length||(!String(message||'').trim()&&!file))return res.status(400).json({error:'message'});
 if(file?.data&&String(file.data).length>14*1024*1024)return res.status(413).json({error:'file too large'});
 const ins=db.prepare('INSERT INTO messages(user_id,from_admin,message,file_name,file_type,file_data,created_at) VALUES(?,?,?,?,?,?,?)');
 const tx=db.transaction(()=>ids.forEach(id=>ins.run(id,1,String(message||'').trim(),String(file?.name||''),String(file?.type||''),String(file?.data||''),now())));
 tx(); res.json({ok:true,count:ids.length,sent:ids.length});
});
app.get('/api/admin/messages/:userId',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 res.json({messages:db.prepare('SELECT * FROM messages WHERE user_id=? ORDER BY id').all(req.params.userId)});
});

app.post('/api/admin/broadcast',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const b=req.body||{}, title=String(b.title||'XCAR').trim(), message=String(b.message||'').trim();
 const target=['all','active','expired','blocked','selected'].includes(b.target)?b.target:'all';
 if(!message)return res.status(400).json({error:'message'});
 const ids=Array.isArray(b.userIds)?b.userIds.map(Number).filter(Boolean):[];
 const expiresAt=Number(b.expiresAt||0);
 const info=db.prepare('INSERT INTO broadcasts(title,message,target,target_user_ids,created_at,expires_at,active) VALUES(?,?,?,?,?,?,1)')
  .run(title,message,target,JSON.stringify(ids),now(),expiresAt);
 // помимо всплывающего окна в приложении (его клиент подхватывает опросом
 // /api/public/broadcasts), пытаемся сразу доставить push-уведомление на все устройства,
 // подписанные на push и попадающие под выбранную аудиторию рассылки; ответ администратору
 // не задерживаем — доставка происходит в фоне, лучшее из возможного (best-effort)
 broadcastPush(target,ids,{title,body:message}).catch(()=>{});
 res.json({ok:true,id:info.lastInsertRowid});
});
app.get('/api/admin/broadcasts',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 res.json({broadcasts:db.prepare('SELECT * FROM broadcasts ORDER BY id DESC').all()});
});
app.post('/api/admin/broadcasts/:id/disable',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 db.prepare('UPDATE broadcasts SET active=0 WHERE id=?').run(req.params.id);
 res.json({ok:true});
});

app.post('/api/admin/restore-settings',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const {userIds=[],text=''}=req.body||{};
 let ids=Array.isArray(userIds)?userIds.map(Number).filter(Boolean):[];
 if(!ids.length)ids=db.prepare('SELECT id FROM users ORDER BY id').all().map(x=>x.id);
 if(!ids.length)return res.status(400).json({error:'no users selected'});
 const restoreText=String(text||'').trim().slice(0,2000);
 const users=db.prepare(`SELECT id,username,payload FROM users WHERE id IN (${ids.map(()=>'?').join(',')})`).all(...ids);
 const ins=db.prepare('INSERT INTO settings_restore_jobs(user_id,settings_json,restore_text,created_at,applied_at) VALUES(?,?,?,?,0)');
 const tx=db.transaction(()=>{
   let created=0;
   for(const u of users){
     let payload={};try{payload=JSON.parse(u.payload||'{}')}catch{}
     const settings=payload&&payload.settings&&typeof payload.settings==='object'?payload.settings:{};
     ins.run(u.id,JSON.stringify(settings),restoreText,now());
     created++;
   }
   return created;
 });
 const created=tx();
 res.json({ok:true,count:created,requested:ids.length});
});
app.get('/api/admin/restore-settings/users',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const rows=db.prepare('SELECT id,username,email,phone,subscription_until,blocked,updated_at,payload FROM users ORDER BY username COLLATE NOCASE').all();
 res.json({users:rows.map(u=>{let p={};try{p=JSON.parse(u.payload||'{}')}catch{};return {id:u.id,username:u.username,email:u.email||'',phone:u.phone||'',subscription_until:u.subscription_until,blocked:u.blocked,updated_at:u.updated_at,hasSettings:!!(p&&p.settings)}})});
});


function decodeStoredFile(raw){try{return Buffer.from(String(raw||''),'base64').toString('utf8')}catch(e){return String(raw||'')}}
function cleanTextFile(raw,mime='text/plain'){
 let t=String(raw||'');
 if(/html/i.test(mime)||/\.html?$/i.test('x.'+mime)){
  t=t.replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ')
     // важно: границы записей в HTML-файле (строка таблицы, абзац, элемент списка, <br>)
     // превращаем в ПЕРЕНОС СТРОКИ, а не в пробел — иначе после удаления остальных тегов
     // все записи склеиваются в одну гигантскую "строку" без \n, и логика поиска конца
     // фрагмента (по границе строки) не может остановиться и "утекает" через весь файл,
     // из-за чего совпадение в пользовательском приложении не отображается
     .replace(/<\s*(br\s*\/?|\/tr|\/p|\/div|\/li|\/h[1-6]|\/td|\/table|\/ul|\/ol)\s*>/gi,'\n')
     .replace(/<[^>]+>/g,' ');
 }
 return t.replace(/&nbsp;/gi,' ').replace(/&amp;/gi,'&').replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/\r/g,'');
}
const DEFAULT_BLACKLIST_HIGHLIGHT={
 color:'#7f1d1d',bg:'#fecaca',sizePercent:150,before:0,afterMode:'line',afterChars:200,
 // текстовые границы и вариант карточки включены по умолчанию, чтобы администратор сразу
 // видел рабочие настройки (пустые начальный/конечный текст ничего не меняют, пока их не
 // заполнят — так что включение по умолчанию безопасно). matchPosition по умолчанию "above" —
 // совпадение показывается аккуратным заголовком над карточкой-предупреждением, а не гигантской
 // плашкой посреди текста (это и выглядело некрасиво до правки)
 boundaryMode:'text',startText:'',endText:'',
 cardVariantEnabled:true,cardVariant:'standard',
 cardBorderColor:'#e4d9f4',cardBorderWidth:1,cardCorner:'rounded',
 matchPosition:'above',
 contextColor:'#7f1d1d',contextBg:''
};
function getBlacklistHighlight(){
 try{
  const raw=setting('blacklist_highlight','');
  if(!raw) return {...DEFAULT_BLACKLIST_HIGHLIGHT};
  const parsed=JSON.parse(raw);
  return {...DEFAULT_BLACKLIST_HIGHLIGHT,...(parsed&&typeof parsed==='object'?parsed:{})};
 }catch(e){return {...DEFAULT_BLACKLIST_HIGHLIGHT};}
}
// вычисляет границы фрагмента вокруг найденного совпадения (индекс hitIdx в original).
// Режим "auto" — старое поведение: N символов до совпадения и конец по строке/N символов.
// Режим "text" — по желанию администратора: фрагмент начинается СРАЗУ ПОСЛЕ указанного
// "начального текста" (если он найден перед совпадением) и заканчивается СРАЗУ ПОСЛЕ
// указанного "конечного текста" (если он найден после совпадения). Если начальный/конечный
// текст не задан или не найден — используется обычное поведение (auto) для этой границы,
// поэтому границы по тексту можно включать по отдельности.
function computeSnippetWindow(original,hitIdx,hl){
 const before=Math.max(0,Number(hl.before)||0);
 const afterMode=hl.afterMode==='chars'?'chars':'line';
 const afterChars=Math.max(10,Number(hl.afterChars)||200);
 let start=Math.max(0,hitIdx-before);
 let end; { const autoEnd=(afterMode==='chars')?Math.min(original.length,hitIdx+afterChars):(()=>{let e=original.indexOf('\n',hitIdx);return e<0?original.length:e;})(); end=autoEnd; }
 if(hl.boundaryMode==='text'){
  const lowerOriginal=original.toLowerCase();
  if(hl.startText){
   const needle=String(hl.startText).toLowerCase();
   const pos=lowerOriginal.lastIndexOf(needle,hitIdx);
   if(pos>=0) start=pos+String(hl.startText).length;
  }
  if(hl.endText){
   const needle=String(hl.endText).toLowerCase();
   const pos=lowerOriginal.indexOf(needle,hitIdx);
   if(pos>=0) end=pos+String(hl.endText).length;
  }
 }
 if(end<start) end=start;
 return {start,end};
}
function blacklistSnippet(text,terms,hl){
 const lines=cleanTextFile(text).split(/\n+/).map(x=>x.trim()).filter(Boolean);
 const lower=text.toLowerCase();
 let idx=-1; for(const term of terms){const i=lower.indexOf(term.toLowerCase()); if(i>=0){idx=i;break;}}
 if(idx>=0){
  hl=hl||getBlacklistHighlight();
  // фрагмент по умолчанию начинается ровно с найденного слова (без текста до него, если
  // "начало отображения" = 0) и заканчивается на конце текущей записи/строки, а не через
  // фиксированное число символов — иначе фрагмент "утекал" в следующую, никак не связанную
  // запись базы. Все параметры границ настраиваются администратором (см. computeSnippetWindow).
  const original=String(text||'').replace(/\r/g,'');
  const {start,end}=computeSnippetWindow(original,idx,hl);
  return original.slice(start,end).replace(/\s+/g,' ').trim();
 }
 return lines.slice(0,2).join(' ').slice(0,360);
}
function blacklistAllMatches(text, q, terms, hl){
 // важно: границы записей ищем по ИСХОДНОМУ тексту с переносами строк — каждая запись
 // чёрного списка обычно занимает одну строку. Склеивать все пробелы/переносы в один пробел
 // (как было раньше) нельзя — из-за этого фрагмент результата "продолжался" в текст
 // следующей, совершенно другой записи вместо того чтобы остановиться на своей
 hl=hl||getBlacklistHighlight();
 const original=String(text||'').replace(/\r/g,'');
 const lower=original.toLowerCase();
 const qLower=String(q||'').toLowerCase();
 const needles=lower.includes(qLower)?[qLower]:terms.map(String).filter(Boolean);
 const found=[];
 for(const needle of needles){let from=0;while(needle&&from<lower.length){const idx=lower.indexOf(needle,from);if(idx<0)break;found.push({idx,term:needle});from=idx+Math.max(1,needle.length);}}
 found.sort((a,b)=>a.idx-b.idx||a.term.length-b.term.length);
 const unique=[];
 for(const hit of found){
  if(unique.some(x=>Math.abs(x.idx-hit.idx)<Math.max(1,Math.min(x.term.length,hit.term.length)*0.8)))continue;
  // фрагмент по умолчанию начинается ровно со слова совпадения (без текста до него) и
  // заканчивается на конце этой же строки/записи (не переходя на следующую запись базы);
  // все параметры границ ("начало"/"конец отображения", текстовые границы) настраиваются
  // администратором — см. computeSnippetWindow
  const {start,end}=computeSnippetWindow(original,hit.idx,hl);
  const snippet=original.slice(start,end).replace(/\s+/g,' ').trim();
  unique.push({term:hit.term,index:hit.idx,snippet});
 }
 return unique;
}

app.get('/api/admin/blacklist/files',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const rows=db.prepare('SELECT id,name,mime,size,created_at,updated_at FROM blacklist_files ORDER BY updated_at DESC').all();
 res.json({files:rows});
});
app.post('/api/admin/blacklist/files',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const name=String(req.body?.name||'').trim(); const mime=String(req.body?.mime||'text/plain').toLowerCase(); const data=String(req.body?.data||'');
 if(!name)return res.status(400).json({error:'name required'});
 if(!/\.(txt|html?|htm)$/i.test(name))return res.status(400).json({error:'Разрешены только TXT и HTML'});
 if(!data)return res.status(400).json({error:'file data required'});
 if(data.length>7*1024*1024)return res.status(413).json({error:'file too large'});
 const nowTs=now();
 db.prepare('INSERT INTO blacklist_files(name,mime,data,size,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET mime=excluded.mime,data=excluded.data,size=excluded.size,updated_at=excluded.updated_at').run(name,mime,data,Math.floor(data.length*0.75),nowTs,nowTs);
 res.json({ok:true});
});
app.delete('/api/admin/blacklist/files/:id',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 db.prepare('DELETE FROM blacklist_files WHERE id=?').run(Number(req.params.id)); res.json({ok:true});
});
app.get('/api/admin/blacklist/files/:id',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const f=db.prepare('SELECT * FROM blacklist_files WHERE id=?').get(Number(req.params.id)); if(!f)return res.status(404).json({error:'not found'});
 res.json({file:f});
});
app.get('/api/admin/blacklist/meta',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const r=db.prepare('SELECT MAX(updated_at) lastUpdatedAt, COUNT(*) count FROM blacklist_files').get();
 const custom=Number(setting('blacklist_update_at','0'))||0;
 res.json({lastUpdatedAt:custom||Number(r?.lastUpdatedAt||0),autoLastUpdatedAt:Number(r?.lastUpdatedAt||0),count:Number(r?.count||0),manual:!!custom});
});
app.post('/api/admin/blacklist/meta',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const value=req.body?.lastUpdatedAt;
 if(value===null||value===undefined||String(value).trim()===''){
   setSetting('blacklist_update_at','0');
   const r=db.prepare('SELECT MAX(updated_at) lastUpdatedAt, COUNT(*) count FROM blacklist_files').get();
   return res.json({ok:true,lastUpdatedAt:Number(r?.lastUpdatedAt||0),manual:false});
 }
 const ts=Number(value);
 if(!Number.isFinite(ts)||ts<0)return res.status(400).json({error:'Неверная дата обновления'});
 setSetting('blacklist_update_at',String(Math.floor(ts)));
 res.json({ok:true,lastUpdatedAt:Math.floor(ts),manual:true});
});
app.get('/api/admin/blacklist/highlight',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 res.json({highlight:getBlacklistHighlight()});
});
app.post('/api/admin/blacklist/highlight',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const b=req.body||{};
 const isHex=v=>/^#[0-9a-fA-F]{3,8}$/.test(String(v||''));
 const clean={
  color:isHex(b.color)?b.color:DEFAULT_BLACKLIST_HIGHLIGHT.color,
  bg:isHex(b.bg)?b.bg:DEFAULT_BLACKLIST_HIGHLIGHT.bg,
  sizePercent:Math.min(500,Math.max(100,Number(b.sizePercent)||DEFAULT_BLACKLIST_HIGHLIGHT.sizePercent)),
  before:Math.min(500,Math.max(0,Number(b.before)||0)),
  afterMode:b.afterMode==='chars'?'chars':'line',
  afterChars:Math.min(2000,Math.max(10,Number(b.afterChars)||DEFAULT_BLACKLIST_HIGHLIGHT.afterChars)),
  // текстовые границы фрагмента (по желанию) — включаются отдельным переключателем
  boundaryMode:b.boundaryMode==='text'?'text':'auto',
  startText:String(b.startText||'').slice(0,200),
  endText:String(b.endText||'').slice(0,200),
  // вариант отображения карточки результата — тоже включается/выключается отдельно
  cardVariantEnabled:!!b.cardVariantEnabled,
  cardVariant:['standard','compact','detailed','accent'].includes(b.cardVariant)?b.cardVariant:DEFAULT_BLACKLIST_HIGHLIGHT.cardVariant,
  // дополнительные настройки карточки: обводка (цвет/толщина), скругление углов,
  // положение совпадения (в тексте / отдельной строкой над карточкой), цвет и фон
  // остального (не выделенного) текста — применяются во всех 3 приложениях
  cardBorderColor:isHex(b.cardBorderColor)?b.cardBorderColor:DEFAULT_BLACKLIST_HIGHLIGHT.cardBorderColor,
  cardBorderWidth:Math.min(10,Math.max(0,Number.isFinite(Number(b.cardBorderWidth))&&b.cardBorderWidth!==''&&b.cardBorderWidth!==undefined&&b.cardBorderWidth!==null?Number(b.cardBorderWidth):DEFAULT_BLACKLIST_HIGHLIGHT.cardBorderWidth)),
  cardCorner:b.cardCorner==='sharp'?'sharp':'rounded',
  matchPosition:b.matchPosition==='above'?'above':'inline',
  contextColor:(b.contextColor==='')?'':(isHex(b.contextColor)?b.contextColor:DEFAULT_BLACKLIST_HIGHLIGHT.contextColor),
  contextBg:(b.contextBg==='')?'':(isHex(b.contextBg)?b.contextBg:DEFAULT_BLACKLIST_HIGHLIGHT.contextBg)
 };
 setSetting('blacklist_highlight',JSON.stringify(clean));
 res.json({ok:true,highlight:clean});
});
app.get('/api/public/blacklist/highlight',(req,res)=>{
 res.json({highlight:getBlacklistHighlight()});
});
// принудительное обновление всех пользовательских приложений — кнопка в шапке админ-панели.
// Приложение пользователя периодически опрашивает /api/public/force-update и, увидев более
// новую метку времени, сама очищает кэш и перезагружается (та же логика, что и при ручном
// удержании кнопки "Обновить приложение" внутри самого приложения).
app.post('/api/admin/force-update-users',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const ts=now();
 setSetting('app_force_update_at',String(ts));
 res.json({ok:true,ts});
});
app.get('/api/public/force-update',(req,res)=>{
 res.json({ts:Number(setting('app_force_update_at','0'))||0});
});
app.get('/api/public/blacklist/meta',(req,res)=>{
 const r=db.prepare('SELECT MAX(updated_at) lastUpdatedAt, COUNT(*) count FROM blacklist_files').get();
 const custom=Number(setting('blacklist_update_at','0'))||0;
 res.json({lastUpdatedAt:custom||Number(r?.lastUpdatedAt||0),autoLastUpdatedAt:Number(r?.lastUpdatedAt||0),count:Number(r?.count||0),manual:!!custom});
});
app.get('/api/public/blacklist/files',(req,res)=>{
 const rows=db.prepare('SELECT id,name,mime,data,size,updated_at FROM blacklist_files ORDER BY name COLLATE NOCASE').all();
 res.json({files:rows.map(f=>({id:f.id,name:f.name,mime:f.mime,data:f.data,size:f.size,updatedAt:f.updated_at}))});
});
app.get('/api/public/blacklist/search',(req,res)=>{
 const q=String(req.query?.q||'').trim();
 if(q.length<2)return res.status(400).json({error:'query required'});
 const terms=q.toLowerCase().split(/\s+/).filter(Boolean);
 const rows=db.prepare('SELECT id,name,mime,data,updated_at FROM blacklist_files ORDER BY name COLLATE NOCASE').all();
 const results=[];
 // показываем файл только при полном совпадении введённого запроса как единой фразы-подстроки,
 // а не когда все отдельные слова запроса просто где-то по отдельности встретились в тексте —
 // иначе в результаты попадали "похожие", но не относящиеся к делу записи
 for(const f of rows){
   const text=cleanTextFile(decodeStoredFile(f.data),f.mime), lower=text.toLowerCase();
   const phrase=lower.includes(q.toLowerCase());
   if(phrase){const matches=blacklistAllMatches(text,q,terms);results.push({id:f.id,filename:f.name,snippet:matches[0]?.snippet||blacklistSnippet(text,terms),matches,count:matches.length,updatedAt:f.updated_at,matched:terms});}
 }
 res.json({query:q,results});
});
app.post('/api/blacklist/search',(req,res)=>{
 const q=String(req.body?.query||'').trim();
 if(q.length<2)return res.status(400).json({error:'query required'});
 const terms=q.toLowerCase().split(/\s+/).filter(Boolean);
 const rows=db.prepare('SELECT id,name,mime,data,updated_at FROM blacklist_files ORDER BY name COLLATE NOCASE').all();
 const results=[];
 // полное совпадение запроса (фраза-подстрока), см. комментарий выше у /api/public/blacklist/search
 for(const f of rows){const text=cleanTextFile(decodeStoredFile(f.data),f.mime),lower=text.toLowerCase();if(lower.includes(q.toLowerCase())){const matches=blacklistAllMatches(text,q,terms);results.push({id:f.id,filename:f.name,snippet:matches[0]?.snippet||blacklistSnippet(text,terms),matches,count:matches.length,updatedAt:f.updated_at,matched:terms});}}
 res.json({query:q,results});
});

app.get('/api/admin/backup',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const b=backupSnapshot();
 res.download(b.dbFile,path.basename(b.dbFile),()=>{try{fs.unlinkSync(b.dbFile);fs.unlinkSync(b.jsonFile)}catch{}});
});
app.get('/api/admin/backups',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const files=fs.readdirSync(BACKUP_DIR).map(name=>{
  const p=path.join(BACKUP_DIR,name),s=fs.statSync(p);
  return {name,size:s.size,created_at:s.mtimeMs,type:name.endsWith('.sqlite')?'database':'json'};
 }).sort((a,b)=>b.created_at-a.created_at);
 res.json({backups:files});
});
app.get('/api/admin/restore-preview/:name',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const safe=path.basename(String(req.params.name||'')); if(!safe.endsWith('.json'))return res.status(400).json({error:'json backup required'});
 const file=path.join(BACKUP_DIR,safe); if(!fs.existsSync(file))return res.status(404).json({error:'backup not found'});
 try{const snap=JSON.parse(fs.readFileSync(file,'utf8'));res.json({users:(snap.users||[]).map(u=>({id:u.id,username:u.username,email:u.email||'',phone:u.phone||'',subscription_until:Number(u.subscription_until||0),blocked:Number(u.blocked||0)}))})}catch(e){res.status(400).json({error:'invalid backup'})}
});
app.post('/api/admin/restore-users',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const {backupName='',userIds=[]}=req.body||{};
 if(!backupName)return res.status(400).json({error:'backup required'});
 const safe=path.basename(String(backupName));
 if(!safe.endsWith('.json'))return res.status(400).json({error:'json backup required'});
 const file=path.join(BACKUP_DIR,safe);
 if(!fs.existsSync(file))return res.status(404).json({error:'backup not found'});
 let snap;try{snap=JSON.parse(fs.readFileSync(file,'utf8'))}catch(e){return res.status(400).json({error:'invalid backup'})}
 const wanted=Array.isArray(userIds)?userIds.map(Number).filter(Boolean):[];
 const source=Array.isArray(snap.users)?snap.users:[];
 const selected=wanted.length?source.filter(u=>wanted.includes(Number(u.id))):source;
 if(!selected.length)return res.status(400).json({error:'no users selected'});
 const restore=()=>db.transaction(()=>{
   const upsert=db.prepare(`UPDATE users SET password_hash=?,email=?,phone=?,subscription_until=?,blocked=?,created_at=?,updated_at=?,payload=? WHERE username=?`);
   const insert=db.prepare(`INSERT INTO users(username,password_hash,email,phone,subscription_until,blocked,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?,?,?)`);
   const byName=db.prepare('SELECT id FROM users WHERE username=?');
   const byId=db.prepare('SELECT id FROM users WHERE id=?');
   const deleteMessages=db.prepare('DELETE FROM messages WHERE user_id=?');
   const insertMessage=db.prepare(`INSERT INTO messages(user_id,from_admin,message,file_name,file_type,file_data,created_at) VALUES(?,?,?,?,?,?,?)`);
   const deleteReq=db.prepare('DELETE FROM subscription_requests WHERE user_id=?');
   const insertReq=db.prepare(`INSERT INTO subscription_requests(user_id,username,name,phone,months,price,status,created_at,decided_at) VALUES(?,?,?,?,?,?,?,?,?)`);
   let restored=0;
   for(const u of selected){
     if(!u.username||!u.password_hash)continue;
     let cur=byName.get(u.username);
     if(cur){
       upsert.run(u.password_hash,u.email||'',u.phone||'',Number(u.subscription_until||0),Number(u.blocked||0),Number(u.created_at||now()),Number(u.updated_at||now()),String(u.payload||'{}'),u.username);
     }else{
       const wantedId=Number(u.id||0);
       if(wantedId>0&&!byId.get(wantedId)){
         db.prepare(`INSERT INTO users(id,username,password_hash,email,phone,subscription_until,blocked,created_at,updated_at,payload) VALUES(?,?,?,?,?,?,?,?,?,?)`).run(wantedId,u.username,u.password_hash,u.email||'',u.phone||'',Number(u.subscription_until||0),Number(u.blocked||0),Number(u.created_at||now()),Number(u.updated_at||now()),String(u.payload||'{}'));
       }else{
         insert.run(u.username,u.password_hash,u.email||'',u.phone||'',Number(u.subscription_until||0),Number(u.blocked||0),Number(u.created_at||now()),Number(u.updated_at||now()),String(u.payload||'{}'));
       }
     }
     cur=byName.get(u.username); if(!cur)continue;
     const uid=cur.id;
     deleteMessages.run(uid);
     deleteReq.run(uid);
     for(const m of (snap.messages||[]).filter(x=>Number(x.user_id)===Number(u.id))) insertMessage.run(uid,Number(m.from_admin||0),String(m.message||''),String(m.file_name||''),String(m.file_type||''),String(m.file_data||''),Number(m.created_at||now()));
     for(const q of (snap.subscriptionRequests||[]).filter(x=>Number(x.user_id)===Number(u.id))) insertReq.run(uid,String(q.username||u.username),String(q.name||''),String(q.phone||''),Number(q.months||0),Number(q.price||0),String(q.status||'pending'),Number(q.created_at||now()),Number(q.decided_at||0));
     restored++;
   }
   return restored;
 })();
 res.json({ok:true,restored,backup:safe});
});
app.get('/api/admin/backups/:name',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const name=path.basename(req.params.name),p=path.join(BACKUP_DIR,name);
 if(!fs.existsSync(p))return res.status(404).json({error:'not found'});
 res.download(p,name);
});

app.listen(PORT,()=>console.log(`XCAR server listening on ${PORT}`));
