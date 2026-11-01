'use strict';
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 10000);
const SCHOOL_ORIGIN = process.env.SCHOOL_ORIGIN || 'https://aprendendo-a-crescer-site-v3.onrender.com';
const ADMIN_ORIGIN = process.env.ADMIN_ORIGIN || 'https://aprendendo-a-crescer-admin.onrender.com';
if (!process.env.DATABASE_URL || !process.env.SETUP_TOKEN || process.env.SETUP_TOKEN.length < 24) {
  console.error('DATABASE_URL ou SETUP_TOKEN ausente/inválido');
  process.exit(1);
}
const pool = new Pool({connectionString:process.env.DATABASE_URL, max:4, connectionTimeoutMillis:12000, idleTimeoutMillis:30000, ssl:{rejectUnauthorized:false}});
const defaults = {
  heroTitle:'Uma infância de descobertas começa aqui.',
  heroSubtitle:'Um universo de cores, descobertas e novas possibilidades. Conheça as etapas da educação infantil da Aprendendo a Crescer.',
  aboutTitle:'O começo de uma linda jornada.',
  aboutText:'Na educação infantil, cada etapa traz novas formas de sentir, explorar e compreender o mundo. A Aprendendo a Crescer está aqui para fazer parte dessa importante fase da vida.',
  aboutText2:'Quer conhecer mais sobre o nosso dia a dia, os espaços e a proposta da escola? Ficaremos felizes em conversar com sua família.',
  courses:['Os primeiros encontros com o mundo, em um tempo de descobertas.','Novos movimentos, vínculos e curiosidades em cada dia.','Descobrindo possibilidades nas brincadeiras e interações.','Imaginação, linguagem e novas maneiras de explorar.','Histórias, perguntas e descobertas que ganham novos sentidos.','Mais autonomia, expressão e preparação para novos caminhos.'],
  registrationTitle:'Vamos conversar sobre o futuro?',
  registrationText:'Escolher uma escola é um passo importante. Conte qual turma você procura e prepare sua mensagem de interesse para entrar em contato com a Aprendendo a Crescer.',
  contactTitle:'Uma conversa pode ser o começo de tudo.',
  contactText:'Quer saber sobre as turmas, as matrículas ou conhecer a Aprendendo a Crescer? Fale pelo WhatsApp (19) 98155-3803 ou consulte nosso endereço para uma visita.',
  whatsapp:'5519981553803',
  email:'',
  address:'Rua Márcio Eduardo Moura, 5 — Jardim Nova Terra (Nova Veneza), Sumaré - SP, CEP 13179-011',
  images:{logo:'',hero:'',about:'',activity1:'',activity2:''}
};
function normalize(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw Object.assign(new Error('Dados inválidos'),{status:400});
  const out={};
  const textFields=['heroTitle','heroSubtitle','aboutTitle','aboutText','aboutText2','registrationTitle','registrationText','contactTitle','contactText','address'];
  for(const key of textFields) {
    const value=payload[key];
    if(typeof value !== 'string' || value.trim().length<2 || value.length>1500) throw Object.assign(new Error('Campo inválido: '+key),{status:400});
    out[key]=value.trim();
  }
  if (!Array.isArray(payload.courses) || payload.courses.length!==6 || payload.courses.some(x=>typeof x !== 'string'||x.trim().length<2||x.length>650)) throw Object.assign(new Error('Descrições das turmas inválidas'),{status:400});
  out.courses=payload.courses.map(x=>x.trim());
  let phone=String(payload.whatsapp||'').replace(/\D/g,'');
  if(phone.length===11) phone='55'+phone;
  if(!/^55\d{10,11}$/.test(phone)) throw Object.assign(new Error('Informe WhatsApp com DDD válido'),{status:400});
  out.whatsapp=phone;
  out.email=String(payload.email||'').trim().toLowerCase();
  if(out.email && (out.email.length>150|| !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(out.email))) throw Object.assign(new Error('E-mail inválido'),{status:400});
  out.images={};
  const photos=payload.images||{};
  for(const key of Object.keys(defaults.images)){
    const v=photos[key]||'';
    if(typeof v !== 'string'||v.length>550000) throw Object.assign(new Error('Imagem muito grande: '+key),{status:400});
    if(v && !/^data:image\/(webp|jpeg|png);base64,[a-zA-Z0-9+/=]+$/.test(v) && !/^https:\/\/[^\s<>"']{8,1500}$/.test(v)) throw Object.assign(new Error('Formato de imagem inválido: '+key),{status:400});
    out.images[key]=v;
  }
  return out;
}
app.use((req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  if(req.path.startsWith('/api/'))res.setHeader('Cache-Control','no-store');
  if(req.path === '/api/public' && req.get('origin') === SCHOOL_ORIGIN){
    res.setHeader('Access-Control-Allow-Origin',SCHOOL_ORIGIN);
    res.setHeader('Vary','Origin');
    res.setHeader('Access-Control-Allow-Methods','GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers','Content-Type');
  }
  if(req.method === 'OPTIONS')return res.sendStatus(204);
  if(!['GET','HEAD','OPTIONS'].includes(req.method) && req.path.startsWith('/api/')){
    const origin=req.get('origin');
    if(origin && origin!==ADMIN_ORIGIN)return res.status(403).json({error:'Origem não autorizada'});
  }
  next();
});
app.use(express.json({limit:'4mb', strict:true}));
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function safeEqual(a,b){const x=Buffer.from(String(a));const y=Buffer.from(String(b));return x.length===y.length && crypto.timingSafeEqual(x,y)}
function passHash(password,salt){return crypto.scryptSync(password,salt,64,{N:16384,r:8,p:1}).toString('hex')}
function cookies(req){const c={};for(const part of (req.headers.cookie||'').split(';')){const i=part.indexOf('=');if(i>0)c[part.slice(0,i).trim()]=part.slice(i+1).trim()}return c}
function setCookie(res,token){res.setHeader('Set-Cookie','school_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800')}
function clearCookie(res){res.setHeader('Set-Cookie','school_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0')}
async function auth(req,res,next){
  try{
    const token=cookies(req).school_session;
    if(!token || !/^[a-f0-9]{64}$/.test(token))return res.status(401).json({error:'Sessão expirada. Entre novamente.'});
    const {rows}=await pool.query("SELECT u.email FROM admin_sessions s JOIN admin_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() LIMIT 1",[sha(token)]);
    if(!rows.length)return res.status(401).json({error:'Sessão expirada. Entre novamente.'});
    req.adminEmail=rows[0].email;next();
  }catch(e){next(e)}
}
let initialized=false;
async function initialize(){
  await pool.query("CREATE TABLE IF NOT EXISTS admin_users (id integer PRIMARY KEY CHECK (id=1),email text NOT NULL,password_hash text NOT NULL,salt text NOT NULL,created_at timestamptz NOT NULL DEFAULT now())");
  await pool.query("CREATE TABLE IF NOT EXISTS admin_sessions (token_hash text PRIMARY KEY,user_id integer NOT NULL REFERENCES admin_users(id),created_at timestamptz NOT NULL DEFAULT now(),expires_at timestamptz NOT NULL)");
  await pool.query("CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions(expires_at)");
  await pool.query("CREATE TABLE IF NOT EXISTS school_content (id integer PRIMARY KEY CHECK (id=1),data jsonb NOT NULL,revision integer NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT now())");
  await pool.query('INSERT INTO school_content(id,data) VALUES (1,$1::jsonb) ON CONFLICT (id) DO NOTHING',[JSON.stringify(defaults)]);
  initialized=true;
}
app.get('/health',(req,res)=>res.status(initialized?200:503).json({ok:initialized}));
app.get('/api/meta',async(req,res,next)=>{try{const q=await pool.query('SELECT EXISTS(SELECT 1 FROM admin_users WHERE id=1) AS configured');res.json({configured:q.rows[0].configured})}catch(e){next(e)}});
app.get('/api/public',async(req,res,next)=>{try{const q=await pool.query('SELECT data,revision FROM school_content WHERE id=1');res.json(q.rows[0]||{data:defaults,revision:1})}catch(e){next(e)}});
app.post('/api/setup',async(req,res,next)=>{try{
  const {token,email,password}=req.body||{};
  if(!safeEqual(token||'',process.env.SETUP_TOKEN))return res.status(403).json({error:'Código de ativação inválido'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email||'')||String(email).length>150)return res.status(400).json({error:'Informe um e-mail válido'});
  if(typeof password!=='string'||password.length<12||password.length>120)return res.status(400).json({error:'A senha deve conter pelo menos 12 caracteres'});
  const salt=crypto.randomBytes(24).toString('hex');
  const result=await pool.query('INSERT INTO admin_users(id,email,password_hash,salt) VALUES(1,$1,$2,$3) ON CONFLICT (id) DO NOTHING RETURNING id',[email.toLowerCase(),passHash(password,salt),salt]);
  if(!result.rowCount)return res.status(409).json({error:'Administrador já configurado'});
  res.json({ok:true});
}catch(e){next(e)}});
const failures=new Map();
app.post('/api/login',async(req,res,next)=>{try{
  const ip=req.ip||'unknown',f=failures.get(ip)||{count:0,until:0};
  if(f.until>Date.now())return res.status(429).json({error:'Muitas tentativas. Tente novamente mais tarde.'});
  const email=String(req.body?.email||'').trim().toLowerCase(),password=req.body?.password;
  const q=await pool.query('SELECT id,email,password_hash,salt FROM admin_users WHERE id=1');
  const user=q.rows[0];
  const good=!!user && safeEqual(email,user.email) && typeof password==='string' && safeEqual(passHash(password,user.salt),user.password_hash);
  if(!good){const count=f.count+1;failures.set(ip,{count,until: count>=6?Date.now()+15*60*1000:0});return res.status(401).json({error:'E-mail ou senha incorretos'})}
  failures.delete(ip);
  const token=crypto.randomBytes(32).toString('hex');
  await pool.query("INSERT INTO admin_sessions(token_hash,user_id,expires_at) VALUES($1,1,now()+interval '7 days')",[sha(token)]);
  setCookie(res,token);res.json({ok:true});
}catch(e){next(e)}});
app.post('/api/logout',auth,async(req,res,next)=>{try{await pool.query('DELETE FROM admin_sessions WHERE token_hash=$1',[sha(cookies(req).school_session)]);clearCookie(res);res.json({ok:true})}catch(e){next(e)}});
app.get('/api/admin/content',auth,async(req,res,next)=>{try{const q=await pool.query('SELECT data,revision,updated_at FROM school_content WHERE id=1');res.json({...q.rows[0],email:req.adminEmail})}catch(e){next(e)}});
app.put('/api/admin/content',auth,async(req,res,next)=>{try{
  const revision=Number(req.body?.revision);
  if(!Number.isInteger(revision)||revision<1)return res.status(400).json({error:'Versão inválida'});
  const data=normalize(req.body?.data);
  const q=await pool.query('UPDATE school_content SET data=$1::jsonb, revision=revision+1,updated_at=now() WHERE id=1 AND revision=$2 RETURNING revision,updated_at',[JSON.stringify(data),revision]);
  if(!q.rowCount)return res.status(409).json({error:'O conteúdo foi alterado em outra sessão. Atualize a página.'});
  res.json({ok:true,...q.rows[0]});
}catch(e){next(e)}});
app.get('/',(req,res)=>res.redirect('/admin'));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));
app.use((err,req,res,next)=>{console.error('Server error:',err.code||err.message);res.status(err.status||500).json({error:err.status?err.message:'Erro interno. Tente novamente.'})});
initialize().then(()=>{app.listen(PORT,'0.0.0.0',()=>console.log('Admin escola ouvindo porta '+PORT))}).catch(e=>{console.error('Erro na inicialização do banco:',e.message);process.exit(1)});
