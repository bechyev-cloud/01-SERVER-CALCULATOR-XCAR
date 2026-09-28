const express=require('express');
const cors=require('cors');
const Database=require('better-sqlite3');
const bcrypt=require('bcryptjs');
const crypto=require('crypto');
const path=require('path');
const fs=require('fs');

const app=express();
app.use(cors());
app.use(express.json({limit:'25mb'}));

const PORT=Number(process.env.PORT||3000);
const DB_FILE=process.env.DB_FILE||path.join(__dirname,'xcar.sqlite');
const BACKUP_DIR=process.env.BACKUP_DIR||path.join(__dirname,'backups');
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
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,from_admin INTEGER,message TEXT,created_at INTEGER
);
CREATE TABLE IF NOT EXISTS broadcasts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT,message TEXT,target TEXT DEFAULT 'all',
 target_user_ids TEXT DEFAULT '',created_at INTEGER,expires_at INTEGER,active INTEGER DEFAULT 1
);
`);

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
const adminUser=process.env.ADMIN_USER||'admin';
const adminPass=process.env.ADMIN_PASSWORD||'CHANGE_ME_NOW';

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
 const monthPrice=Number(setting('month_price',process.env.MONTH_PRICE||500));
 return {
  monthPrice,
  discounts:{
   1:Number(setting('discount_1',0)),
   3:Number(setting('discount_3',10)),
   6:Number(setting('discount_6',15)),
   12:Number(setting('discount_12',20))
  },
  bank:setting('pay_bank',process.env.PAY_BANK||'Сбербанк'),
  cardNumber:setting('pay_card',process.env.PAY_CARD||''),
  recipient:setting('pay_recipient',process.env.PAY_RECIPIENT||''),
  phone:setting('pay_phone',process.env.PAY_PHONE||''),
  qrText:setting('pay_qr_text',''),
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
  users:db.prepare('SELECT id,username,email,phone,subscription_until,blocked,created_at,updated_at,payload FROM users').all(),
  subscriptionRequests:db.prepare('SELECT * FROM subscription_requests').all(),
  messages:db.prepare('SELECT * FROM messages').all(),
  broadcasts:db.prepare('SELECT * FROM broadcasts').all(),
  settings:db.prepare('SELECT * FROM app_settings').all()
 };
 fs.writeFileSync(jsonOut,JSON.stringify(snapshot,null,2),'utf8');
 return {stamp,dbFile:dbOut,jsonFile:jsonOut};
}
function cleanupBackups(){
 const files=fs.readdirSync(BACKUP_DIR).filter(f=>f.endsWith('.sqlite')||f.endsWith('.json'));
 const max=Number(process.env.BACKUP_RETENTION||30)*2;
 if(files.length>max){
  files.sort();
  for(const f of files.slice(0,files.length-max)){try{fs.unlinkSync(path.join(BACKUP_DIR,f))}catch{}}
 }
}
function dailyBackup(){
 try{backupSnapshot();cleanupBackups();console.log('XCAR daily backup created');}
 catch(e){console.error('backup error',e.message);}
}
setInterval(dailyBackup,24*60*60*1000);
setTimeout(dailyBackup,15000);

app.get('/health',(req,res)=>res.json({ok:true,time:now(),server:'XCAR'}));

app.get('/api/public/config',(req,res)=>{
 const url=setting('client_server_url',process.env.CLIENT_SERVER_URL||'https://zero1-server-calculator-xcar.onrender.com');
 res.json({ok:true,clientServerUrl:url});
});

app.get('/api/public/subscription',(req,res)=>res.json(publicSubscription()));

app.get('/api/public/broadcasts',(req,res)=>{
 const t=now();
 const all=db.prepare(`SELECT * FROM broadcasts WHERE active=1 AND (expires_at=0 OR expires_at>?) ORDER BY id DESC LIMIT 10`).all(t);
 res.json({broadcasts:all.map(x=>({id:x.id,title:x.title,message:x.message,created_at:x.created_at,expires_at:x.expires_at}))});
});

app.get('/api/public/broadcasts/for-user',(req,res)=>{
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
});

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
 res.json({ok:true,updatedAt:t,subscriptionUntil:u.subscription_until,payload});
});

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
 res.json({messages:db.prepare('SELECT id,from_admin,message,created_at FROM messages WHERE user_id=? ORDER BY id').all(u.id)});
});
app.post('/api/messages',(req,res)=>{
 const u=userAuth(req);if(!u)return res.status(401).json({error:'auth'});
 const message=String(req.body?.message||'').trim();
 if(!message)return res.status(400).json({error:'message'});
 db.prepare('INSERT INTO messages(user_id,from_admin,message,created_at) VALUES(?,?,?,?)').run(u.id,0,message,now());
 res.json({ok:true});
});

app.get('/api/admin/config',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 res.json({
  clientServerUrl:setting('client_server_url',process.env.CLIENT_SERVER_URL||'https://zero1-server-calculator-xcar.onrender.com'),
  trialDays:Number(setting('trial_days',30)),
  ...publicSubscription()
 });
});
app.post('/api/admin/config',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const b=req.body||{},url=String(b.clientServerUrl||'').trim();
 if(url&&!/^https?:\/\//i.test(url))return res.status(400).json({error:'invalid url'});
 if(url)setSetting('client_server_url',url.replace(/\/+$/,''));
 for(const k of ['trialDays','monthPrice','discount_1','discount_3','discount_6','discount_12','pay_bank','pay_card','pay_recipient','pay_phone','pay_qr_text','pay_instruction']){
  if(b[k]!==undefined){
   const map={trialDays:'trial_days',monthPrice:'month_price',discount_1:'discount_1',discount_3:'discount_3',discount_6:'discount_6',discount_12:'discount_12',pay_bank:'pay_bank',pay_card:'pay_card',pay_recipient:'pay_recipient',pay_phone:'pay_phone',pay_qr_text:'pay_qr_text',pay_instruction:'pay_instruction'};
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
 const {userId,message}=req.body||{};
 if(!userId||!String(message||'').trim())return res.status(400).json({error:'message'});
 db.prepare('INSERT INTO messages(user_id,from_admin,message,created_at) VALUES(?,?,?,?)').run(userId,1,String(message).trim(),now());
 res.json({ok:true});
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
app.get('/api/admin/backups/:name',(req,res)=>{
 if(!adminAuth(req))return res.status(401).json({error:'admin auth'});
 const name=path.basename(req.params.name),p=path.join(BACKUP_DIR,name);
 if(!fs.existsSync(p))return res.status(404).json({error:'not found'});
 res.download(p,name);
});

app.listen(PORT,()=>console.log(`XCAR server listening on ${PORT}`));
