const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(ROOT, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SESSION_SECRET_FILE = path.join(DATA_DIR, 'session-secret.txt');
const USERS_DIR = path.join(DATA_DIR, 'users');
for (const dir of [DATA_DIR, UPLOAD_DIR, USERS_DIR]) fs.mkdirSync(dir, { recursive: true });
// Keep the session key stable between restarts, so existing login cookies remain valid.
// Production deployments should set SESSION_SECRET through their hosting environment.
function getSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  try {
    if (fs.existsSync(SESSION_SECRET_FILE)) {
      const saved = fs.readFileSync(SESSION_SECRET_FILE, 'utf8').trim();
      if (saved.length >= 32) return saved;
    }
  } catch {}
  const generated = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SESSION_SECRET_FILE, generated, { mode: 0o600 });
  return generated;
}
const SESSION_SECRET = getSessionSecret();

const seed = {
  users: [],
  projects: [
    { id:'seed1', title:'Pixel World', language:'JavaScript', category:'Игра', description:'Небольшой пиксельный мир, в котором можно исследовать карту и строить собственные уровни.', author:'PixelFox', likes:12, likedBy:[], symbol:'▦', theme:'mint', files:[], created:Date.now()-100000 },
    { id:'seed2', title:'Code Notes', language:'Python', category:'Приложение', description:'Простые заметки для программистов с подсветкой важных идей и быстрым поиском.', author:'CodeNova', likes:8, likedBy:[], symbol:'{ }', theme:'blue', files:[], created:Date.now()-200000 },
    { id:'seed3', title:'Block Builder', language:'C#', category:'Игра', description:'Прототип игры с блоками, строительством и небольшим инвентарём.', author:'BlockCraft', likes:16, likedBy:[], symbol:'▧', theme:'orange', files:[], created:Date.now()-300000 },
    { id:'seed4', title:'Mini Portfolio', language:'HTML / CSS', category:'Сайт', description:'Минималистичная страница-портфолио с карточками работ и адаптивной сеткой.', author:'CodeNova', likes:5, likedBy:[], symbol:'</>', theme:'blue', files:[], created:Date.now()-400000 }
  ]
};
function loadDb() {
  try { const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); if (Array.isArray(d.users) && Array.isArray(d.projects)) return d; } catch {}
  fs.writeFileSync(DB_FILE, JSON.stringify(seed, null, 2)); return structuredClone(seed);
}
let db = loadDb();
let writeQueue = Promise.resolve();
function persist() {
  writeQueue = writeQueue.then(async () => {
    await fs.promises.writeFile(DB_FILE + '.tmp', JSON.stringify(db, null, 2));
    await fs.promises.rename(DB_FILE + '.tmp', DB_FILE);
    const index = [];
    for (const u of db.users) {
      const file = crypto.createHash('sha256').update(u.name.toLowerCase()).digest('hex') + '.json';
      const userProjects = db.projects.filter(p => p.author === u.name).map(p => ({
        id:p.id, title:p.title, language:p.language, category:p.category,
        description:p.description, created:p.created, files:(p.files||[]).map(f=>({id:f.id,name:f.name,size:f.size}))
      }));
      await fs.promises.writeFile(path.join(USERS_DIR,file), JSON.stringify({name:u.name,bio:u.bio||'',projects:userProjects},null,2));
      index.push({ name:u.name, file });
    }
    await fs.promises.writeFile(path.join(USERS_DIR,'index.json'), JSON.stringify(index,null,2));
  });
  return writeQueue;
}
app.disable('x-powered-by');
// Hosting providers such as Render terminate HTTPS at a reverse proxy.
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(session({ secret: SESSION_SECRET, resave:false, saveUninitialized:false, cookie:{ httpOnly:true, sameSite:'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 } }));
app.get('/healthz', (req,res) => res.status(200).json({ ok:true }));
app.get('/', (req,res) => res.sendFile(path.join(ROOT, 'index.html')));
app.get('/index.html', (req,res) => res.sendFile(path.join(ROOT, 'index.html')));
app.use('/uploads', express.static(UPLOAD_DIR, { dotfiles:'deny', index:false, fallthrough:false }));
const upload = multer({
  storage: multer.diskStorage({ destination: UPLOAD_DIR, filename: (req,file,cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).slice(0,12).replace(/[^.a-zA-Z0-9]/g,'')) }),
  limits: { fileSize: 25 * 1024 * 1024, files: 11, fields: 10 },
  fileFilter: (req,file,cb) => { if (file.fieldname === 'image' && !file.mimetype.startsWith('image/')) return cb(new Error('Картинка должна быть изображением.')); cb(null,true); }
});
const safeUser = u => ({ name:u.name, bio:u.bio || '' });
const safeProject = (p, viewer) => ({ ...p, liked: !!viewer && (p.likedBy || []).includes(viewer), imageUrl:p.imageFile ? '/uploads/' + encodeURIComponent(p.imageFile.storedName) : '' });
function auth(req,res,next) { if (!req.session.user) return res.status(401).json({error:'Сначала войди в аккаунт.'}); next(); }
function cleanName(v) { return String(v || '').trim(); }
app.get('/api/state', (req,res) => res.json({ users:db.users.map(safeUser), projects:db.projects.map(p=>safeProject(p,req.session.user)), currentUser:req.session.user || '' }));
app.post('/api/register', async (req,res) => {
  const name=cleanName(req.body.name), password=String(req.body.password || '');
  if (!/^[\p{L}\p{N}_ .-]{2,24}$/u.test(name)) return res.status(400).json({error:'Имя: 2–24 символа, буквы, цифры, пробел, точка, дефис или подчёркивание.'});
  if (password.length < 8 || password.length > 100) return res.status(400).json({error:'Пароль должен содержать от 8 до 100 символов.'});
  if (db.users.some(u=>u.name.toLowerCase()===name.toLowerCase())) return res.status(409).json({error:'Это имя уже занято.'});
  const u={name,passwordHash:await bcrypt.hash(password,12),bio:''}; db.users.push(u); req.session.user=name; await persist(); res.status(201).json({user:safeUser(u)});
});
app.post('/api/login', async (req,res) => { const name=cleanName(req.body.name), password=String(req.body.password||''); const u=db.users.find(x=>x.name.toLowerCase()===name.toLowerCase()); if(!u || !u.passwordHash || !(await bcrypt.compare(password,u.passwordHash))) return res.status(401).json({error:'Неверное имя пользователя или пароль.'}); req.session.user=u.name; res.json({user:safeUser(u)}); });
app.post('/api/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('connect.sid');res.json({ok:true})}));
// Portable account file uses a random revocable token; it never contains the user's password.
// GET is used for export because some hosting/security layers block POST download endpoints.
async function sendAccountExport(req,res){
  const u=db.users.find(x=>x.name===req.session.user);
  if(!u)return res.status(404).json({error:'Пользователь не найден.'});
  const token=crypto.randomBytes(32).toString('hex');
  u.accountTokenHash=crypto.createHash('sha256').update(token).digest('hex');
  await persist();
  res.set('Cache-Control','no-store');
  res.json({type:'devspace-account',version:1,name:u.name,token,createdAt:new Date().toISOString()});
}
app.get('/api/account/export',auth,sendAccountExport);
app.post('/api/account/export',auth,sendAccountExport); // Backward compatibility with older site copies.
app.post('/api/account/import',async(req,res)=>{
  const name=cleanName(req.body.name), token=String(req.body.token||'');
  if(req.body.type!=='devspace-account'||!name||!/^[a-f0-9]{64}$/i.test(token))return res.status(400).json({error:'Файл аккаунта повреждён или имеет неверный формат.'});
  const u=db.users.find(x=>x.name.toLowerCase()===name.toLowerCase());
  const tokenHash=crypto.createHash('sha256').update(token).digest('hex');
  if(!u||!u.accountTokenHash||!crypto.timingSafeEqual(Buffer.from(tokenHash,'hex'),Buffer.from(u.accountTokenHash,'hex')))return res.status(401).json({error:'Файл аккаунта недействителен. Войди по паролю и скачай новый файл.'});
  req.session.user=u.name;
  res.json({user:safeUser(u)});
});
app.patch('/api/profile',auth,async(req,res)=>{const u=db.users.find(x=>x.name===req.session.user);if(!u)return res.status(404).json({error:'Пользователь не найден.'});u.bio=String(req.body.bio||'').slice(0,240);await persist();res.json({user:safeUser(u)});});
app.post('/api/projects',auth,upload.fields([{name:'files',maxCount:10},{name:'image',maxCount:1}]),async(req,res)=>{
  const title=String(req.body.title||'').trim(); if(!title || title.length>80){cleanupUploads(req.files);return res.status(400).json({error:'Название проекта обязательно (до 80 символов).'});}
  const files=(req.files?.files||[]).map(f=>({id:path.basename(f.filename),name:path.basename(f.originalname).slice(0,180),size:f.size,storedName:f.filename,mime:f.mimetype}));
  const img=req.files?.image?.[0]; const p={id:crypto.randomUUID(),title,language:String(req.body.language||'Другой').slice(0,40),category:String(req.body.category||'Другое').slice(0,40),description:String(req.body.description||'').slice(0,1200),author:req.session.user,likes:0,likedBy:[],symbol:['</>','{ }','▦','✦','◈'][Math.floor(Math.random()*5)],theme:['mint','blue','orange'][db.projects.length%3],files,imageFile:img?{storedName:img.filename,name:path.basename(img.originalname)}:null,created:Date.now()};db.projects.unshift(p);await persist();res.status(201).json(safeProject(p,req.session.user));
});
function cleanupUploads(files){if(!files)return;for(const group of Object.values(files))for(const f of group)fs.promises.unlink(f.path).catch(()=>{});}
app.post('/api/projects/:id/like',auth,async(req,res)=>{const p=db.projects.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'Проект не найден.'});p.likedBy=p.likedBy||[];const i=p.likedBy.indexOf(req.session.user);if(i>=0){p.likedBy.splice(i,1);p.likes=Math.max(0,(p.likes||0)-1)}else{p.likedBy.push(req.session.user);p.likes=(p.likes||0)+1}await persist();res.json(safeProject(p,req.session.user));});
app.delete('/api/projects/:id',auth,async(req,res)=>{const i=db.projects.findIndex(p=>p.id===req.params.id);if(i<0)return res.status(404).json({error:'Проект не найден.'});const p=db.projects[i];if(p.author!==req.session.user)return res.status(403).json({error:'Удалять можно только свои проекты.'});db.projects.splice(i,1);for(const f of [...(p.files||[]),...(p.imageFile?[p.imageFile]:[])])if(f.storedName)fs.promises.unlink(path.join(UPLOAD_DIR,f.storedName)).catch(()=>{});await persist();res.json({ok:true});});
app.get('/api/projects/:id/files/:fileId',(req,res)=>{const p=db.projects.find(x=>x.id===req.params.id);const f=p?.files?.find(x=>x.id===req.params.fileId);if(!f)return res.status(404).send('Файл не найден');const target=path.join(UPLOAD_DIR,path.basename(f.storedName));if(!fs.existsSync(target))return res.status(404).send('Файл отсутствует на сервере');res.download(target,f.name);});
app.use((err,req,res,next)=>{if(err instanceof multer.MulterError){const msg=err.code==='LIMIT_FILE_SIZE'?'Файл слишком большой (максимум 25 МБ).':'Слишком много файлов или полей.';return res.status(400).json({error:msg});}if(err)return res.status(400).json({error:err.message||'Ошибка запроса.'});next();});
const port=Number(process.env.PORT)||3000;
app.listen(port,'0.0.0.0',()=>console.log(`DevSpace запущен: https://vitushakagame-creator.github.io/dev_locator-xp/:${port}`));
