import http from "node:http";
import { readFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, createHash, timingSafeEqual } from "node:crypto";
import { parseInquiry, attachmentDisposition } from "./inquiry-data.mjs";
import { model } from "./validation.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const password = process.env.PORTFOLIO_ADMIN_PASSWORD;
if (!password || password.length < 12) {
  console.error("Set PORTFOLIO_ADMIN_PASSWORD to a private password of at least 12 characters.");
  process.exit(1);
}
const html = readFileSync(path.join(root, "index.html"));
const storage = process.env.PORTFOLIO_DATA_DIR || path.join(root, ".portfolio-data");
mkdirSync(storage, { recursive: true, mode: 0o700 });
const db = new DatabaseSync(path.join(storage, "portfolio.sqlite"));
db.exec(`PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS portfolio (id INTEGER PRIMARY KEY, version INTEGER NOT NULL, content TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS inquiries (id TEXT PRIMARY KEY, created INTEGER NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, service TEXT NOT NULL, budget TEXT NOT NULL, brief TEXT NOT NULL);`);
const columns = new Set(db.prepare("PRAGMA table_info(inquiries)").all().map(row => row.name));
for (const [name, fallback] of [["phone","''"],["preferred","'email'"]]) {
  if (!columns.has(name)) db.exec("ALTER TABLE inquiries ADD COLUMN " + name + " TEXT NOT NULL DEFAULT " + fallback);
}
db.exec("CREATE TABLE IF NOT EXISTS inquiry_files (inquiry TEXT NOT NULL, idx INTEGER NOT NULL, name TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(inquiry,idx))");
const sessions = new Map();
const attempts = new Map();
const ttl = 8 * 3600_000;
const sweep = setInterval(() => {
  for (const [key, end] of sessions) if (end <= Date.now()) sessions.delete(key);
  for (const [ip, entry] of attempts) if (entry.end <= Date.now()) attempts.delete(ip);
}, 60_000).unref();

function reply(res, status, data, extra = {}) {
  res.writeHead(status, {"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...extra});
  res.end(JSON.stringify(data));
}
const digest = value => createHash("sha256").update(value).digest();
function authorized(req) {
  const token = (req.headers.cookie || "").split(";").map(s=>s.trim()).find(s=>s.startsWith("folio_session="))?.slice(14);
  return token && (sessions.get(token) || 0) > Date.now();
}
function failure(status, message) { return Object.assign(new Error(message), {status}); }
async function readJson(req, limit) {
  if (!String(req.headers["content-type"] || "").startsWith("application/json")) throw failure(415,"استخدم طلب JSON.");
  if (Number(req.headers["content-length"]) > limit) throw failure(413,"حجم البيانات كبير.");
  const chunks=[]; let total=0;
  for await (const data of req) { total+=data.length; if(total>limit)throw failure(413,"حجم البيانات كبير.");chunks.push(data); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw failure(400,"راجع تنسيق البيانات."); }
}
const textOk=(value,max,required=false)=>typeof value==="string"&&value.length<=max&&(!required||Boolean(value.trim()));
const server=http.createServer(async(req,res)=>{
  try {
    const url=new URL(req.url,"http://localhost"),key=req.method+" "+url.pathname;
    if (req.method!=="GET" && req.headers["sec-fetch-site"]==="cross-site") throw failure(403,"طلب غير مسموح.");
    if (req.method!=="GET" && req.headers.origin && new URL(req.headers.origin).host!==req.headers.host) throw failure(403,"طلب غير مسموح.");
    if (key==="GET /" || key==="GET /index.html") {
      res.writeHead(200,{"content-type":"text/html; charset=utf-8","cache-control":"no-cache","x-content-type-options":"nosniff"});res.end(html);return;
    }
    if(key==="GET /api/content") {
      const row=db.prepare("SELECT version, content FROM portfolio WHERE id=1").get();
      reply(res,200,{app:"fady-portfolio",version:row?.version||0,content:row?JSON.parse(row.content):null,owner:Boolean(authorized(req))});return;
    }
    if(key==="POST /api/login") {
      const ip=req.socket.remoteAddress||"local",now=Date.now();
      const prior=attempts.get(ip);
      const entry=prior&&prior.end>now?prior:{count:0,end:now+10*60_000};
      if(entry.count>=12)throw failure(429,"انتظر عشر دقايق قبل المحاولة تاني.");
      const data=await readJson(req,8192);
      if(!textOk(data?.password,2048,true)||!timingSafeEqual(digest(data.password),digest(password))) {
        entry.count++;attempts.set(ip,entry);throw failure(403,"كلمة المرور غير صحيحة.");
      }
      attempts.delete(ip);
      const token=randomBytes(32).toString("hex"); sessions.set(token,now+ttl);
      const local=/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(req.headers.host||"");
      reply(res,200,{ok:true},{"set-cookie":"folio_session="+token+"; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"+(local?"":"; Secure")});return;
    }
    if(key==="POST /api/inquiry"){
      const request = new Request("http://localhost/api/inquiry", {method:"POST", headers:req.headers,body:req,duplex:"half"});
      const {id,name,email,phone,preferred,service,budget,brief,files} = await parseInquiry(request);
      const attachments = await Promise.all(files.map(async file=>({name:file.name,bytes:Buffer.from(await file.arrayBuffer())})));
      db.exec("BEGIN IMMEDIATE");
      try {
        const added = db.prepare("INSERT OR IGNORE INTO inquiries(id,created,name,email,phone,preferred,service,budget,brief) VALUES(?,?,?,?,?,?,?,?,?)").run(id,Date.now(),name,email,phone,preferred,service,budget,brief);
        if (added.changes) {
          const insert = db.prepare("INSERT INTO inquiry_files(inquiry,idx,name,bytes) VALUES(?,?,?,?)");
          attachments.forEach((file,i)=>insert.run(id,i,file.name,file.bytes));
        }
        db.exec("COMMIT");
      } catch(e) { db.exec("ROLLBACK"); throw e; }
      reply(res,201,{received:true});return;
    }
    if(key==="GET /api/inbox/attachment"){
      if(!authorized(req))throw failure(403,"سجّل الدخول إلى لوحة الإدارة.");
      const index=url.searchParams.get("index") || "";
      const file=/^\d+$/.test(index) && db.prepare("SELECT name,bytes FROM inquiry_files WHERE inquiry=? AND idx=?").get(url.searchParams.get("id") || "", Number(index));
      if(!file)throw failure(404,"المرفق غير موجود.");
      res.writeHead(200,{"content-type":"application/pdf","content-disposition":attachmentDisposition(file.name),"cache-control":"private,no-store","x-content-type-options":"nosniff"});
      res.end(Buffer.from(file.bytes));return;
    }
    if(key==="PUT /api/content" || key==="GET /api/inbox"){
      if(!authorized(req))throw failure(403,"سجّل الدخول إلى لوحة الإدارة.");
      if(req.method==="GET"){
        const offset=Math.max(0,Math.trunc(Number(url.searchParams.get("offset")))||0);
        const rows=db.prepare("SELECT * FROM inquiries ORDER BY created DESC,id LIMIT 50 OFFSET ?").all(offset);
        const list=db.prepare("SELECT name,length(bytes) AS size FROM inquiry_files WHERE inquiry=? ORDER BY idx");
        reply(res,200,{rows:rows.map(row=>({...row,attachments:list.all(row.id)}))});return;
      }
      const payload=await readJson(req,48*1024*1024);
      const check=model.safeParse(payload?.content);
      if(!check.success || !Number.isSafeInteger(payload.version)||payload.version<0) throw failure(400,"راجع البيانات والروابط.");
      const c=check.data, ids=new Set(c.projects.map(p=>p.id));
      if(ids.size!==c.projects.length||c.projects.some(p=>!(p.title.en.trim()||p.title.ar.trim())||!p.cover||(p.direct&&!p.url))||c.experience.some(e=>!(e.role.ar.trim()||e.role.en.trim()))||new Set(c.experience.map(e=>e.id)).size!==c.experience.length)throw failure(400,"راجع اسم وغلاف كل مشروع ومسمى كل خبرة.");
      const version=payload.version,content=JSON.stringify(c);
      const changes=version===0?db.prepare("INSERT OR IGNORE INTO portfolio(id,version,content) VALUES(1,1,?)").run(content).changes:db.prepare("UPDATE portfolio SET version=version+1,content=? WHERE id=1 AND version=?").run(content,version).changes;
      if(!changes)throw failure(409,"الموقع اتعدّل في نافذة تانية. حدّث الصفحة قبل الحفظ.");
      reply(res,200,{version:version+1});return;
    }
    reply(res,404,{error:"Not found"});
  } catch(error) {
    if(!res.headersSent) reply(res,error.status||500,{error:error.status?error.message:"تعذّر إكمال العملية."});
    else res.end();
  }
});
server.listen(Number(process.env.PORT)||3000,process.env.HOST||"0.0.0.0",()=>console.log("Portfolio listening on port "+server.address().port));
