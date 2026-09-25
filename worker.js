// InfoHub Max — Cloudflare Worker (API + নিরাপত্তা)। ডেটা: KV binding "DB"
const E=new TextEncoder(),COLS=['articles','categories','users','affiliates','ads','products','businesses','jobs','earnings'],
PUB=['siteName','proPrice','elitePrice','bkash','bank','bankAccount','holder','swift'],DAY=864e5,
DEF={siteName:'InfoHub Max',proPrice:'149',elitePrice:'499',bkash:'',bank:'Future Islamic Bank',bankAccount:'',holder:'',swift:''};
const J=(d,s=200,h={})=>new Response(JSON.stringify(d),{status:s,headers:{'content-type':'application/json;charset=utf-8','cache-control':'no-store',
 'x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'strict-origin-when-cross-origin','permissions-policy':'camera=(), microphone=(), geolocation=()',...h}});
const er=(m,s=400)=>J({error:m},s);
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))),ub=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const eq=(a,b)=>{if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0};
async function hash(pw,salt=crypto.getRandomValues(new Uint8Array(16))){const k=await crypto.subtle.importKey('raw',E.encode(pw),'PBKDF2',false,['deriveBits']);return b64(salt)+'.'+b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:100000},k,256))}
async function verify(pw,h){if(typeof pw!=='string'||!h)return false;return eq(await hash(pw,ub(h.split('.')[0])),h)}
const hk=env=>crypto.subtle.importKey('raw',E.encode(env.SESSION_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
async function cookie(env){const p=btoa(JSON.stringify({exp:Date.now()+18e5})),s=b64(await crypto.subtle.sign('HMAC',await hk(env),E.encode(p)));return `ih_s=${p}.${s}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1800`}
async function check(env,t){if(!t)return false;const[p,s]=t.split('.');if(!s)return false;if(!eq(b64(await crypto.subtle.sign('HMAC',await hk(env),E.encode(p))),s))return false;try{return JSON.parse(atob(p)).exp>Date.now()}catch{return false}}
const rd=async(env,k,d)=>JSON.parse(await env.DB.get(k)||'null')??d;
const wr=(env,k,v)=>env.DB.put(k,JSON.stringify(v));
async function audit(env,ip,a){const l=await rd(env,'audit',[]);l.unshift({t:new Date().toISOString(),ip,a});await wr(env,'audit',l.slice(0,200))}
async function limit(env,key,max,ttl){const k='rl:'+key,n=+(await env.DB.get(k)||0);if(n>=max)return false;await env.DB.put(k,String(n+1),{expirationTtl:ttl});return true}
function clean(o){const r={};for(const k in o){if(!/^[a-zA-Z]{1,30}$/.test(k)||['id','createdAt','updatedAt'].includes(k))continue;const v=o[k];
 if(typeof v==='string'){if(k==='url'&&v&&!/^https?:\/\/[^\s]+$/.test(v))throw new Error('!লিংক http/https দিয়ে শুরু হতে হবে');
  if(k==='slug'&&!/^[a-z0-9-]{1,80}$/.test(v))throw new Error('!slug-এ শুধু ইংরেজি ছোট হাতের অক্ষর, সংখ্যা ও - দিন');r[k]=v.slice(0,20000)}
 else if(typeof v==='number'||typeof v==='boolean')r[k]=v}return r}
function parse(a){return{slug:a.slug,cat:a.cat||'',title:a.title,summary:a.summary||'',updated:(a.updatedAt||'').slice(0,10),
 tags:(a.tags||'').split(',').map(s=>s.trim()).filter(Boolean),
 body:(a.body||'').split(/\n{2,}/).map(s=>s.trim()).filter(Boolean).map(s=>s.startsWith('## ')?['h',s.slice(3)]:['p',s]),
 faq:(a.faq||'').split('\n').map(l=>l.split('|').map(s=>s.trim())).filter(x=>x.length>1&&x[0]),
 sources:(a.sources||'').split('\n').map(s=>s.trim()).filter(Boolean)}}
const XE=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function feeds(env,u,p){
 if(p!=='/sitemap.xml'&&p!=='/rss.xml')return null;
 const s=await rd(env,'settings',DEF),origin=u.origin,site=s.siteName||'InfoHub Max',arts=(await rd(env,'articles',[])).filter(x=>x.status==='published'&&x.slug);
 if(p==='/sitemap.xml'){
  const urls=[`<url><loc>${origin}/</loc></url>`].concat(arts.map(a=>`<url><loc>${origin}/#/a/${XE(a.slug)}</loc><lastmod>${XE(a.updatedAt||'').slice(0,10)}</lastmod></url>`));
  return new Response(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.join('')}</urlset>`,{headers:{'content-type':'application/xml;charset=utf-8','cache-control':'public, max-age=300','x-content-type-options':'nosniff'}})}
 const items=arts.slice(0,50).map(a=>`<item><title>${XE(a.title)}</title><link>${origin}/#/a/${XE(a.slug)}</link><guid>${origin}/#/a/${XE(a.slug)}</guid><description>${XE(a.summary||'')}</description></item>`);
 return new Response(`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>${XE(site)}</title><link>${origin}/</link><description>${XE(site)}</description>${items.join('')}</channel></rss>`,{headers:{'content-type':'application/xml;charset=utf-8','cache-control':'public, max-age=300','x-content-type-options':'nosniff'}})}
export default{async fetch(req,env){
 const u=new URL(req.url),p=u.pathname;
 if(!p.startsWith('/api/')){
  if(env.DB){const f=await feeds(env,u,p).catch(()=>null);if(f)return f}
  return env.ASSETS.fetch(req)}
 if(!env.DB||!env.SESSION_SECRET)return er('সার্ভার সেটআপ অসম্পূর্ণ: KV "DB" বা SESSION_SECRET নেই',500);
 try{return await route(req,env,u,p)}catch(e){return e.message[0]==='!'?er(e.message.slice(1)):er('সার্ভার ত্রুটি',500)}}};
async function route(req,env,u,p){
 const m=req.method,ip=req.headers.get('cf-connecting-ip')||'x',org=req.headers.get('origin');
 if(m!=='GET'&&org&&org!==u.origin)return er('অনুমোদিত নয়',403);
 if(p==='/api/public/data'&&m==='GET'){
  const[a,c,ad,s,af,pr,bz,jb]=await Promise.all([rd(env,'articles',[]),rd(env,'categories',[]),rd(env,'ads',[]),rd(env,'settings',DEF),rd(env,'affiliates',[]),rd(env,'products',[]),rd(env,'businesses',[]),rd(env,'jobs',[])]),o={};
  PUB.forEach(k=>o[k]=s[k]??'');
  return J({articles:a.filter(x=>x.status==='published'&&x.slug&&x.title).map(parse),categories:c.map(x=>({id:x.id,name:x.name})),
   ads:ad.filter(x=>x.status==='approved').map(x=>({title:x.title,url:x.url,text:x.text})),
   affiliates:af.map(x=>({name:x.name,url:x.url,commission:x.commission})),
   products:pr.map(x=>({title:x.title,price:x.price,url:x.url})),
   businesses:bz.map(x=>({name:x.name,phone:x.phone,address:x.address,url:x.url})),
   jobs:jb.map(x=>({title:x.title,company:x.company,url:x.url})),
   settings:o},200,{'cache-control':'public, max-age=60'})}
 if(p==='/api/public/ad-request'&&m==='POST'){
  if(!await limit(env,'ad:'+ip,3,3600))return er('অনেক অনুরোধ হয়েছে। পরে চেষ্টা করুন।',429);
  const b=await req.json().catch(()=>({})),t=x=>typeof x==='string'?x.trim().slice(0,300):'',o={title:t(b.title),url:t(b.url),text:t(b.text),contact:t(b.contact)};
  if(!o.title||!/^https:\/\/[^\s]+$/.test(o.url)||!o.contact)return er('শিরোনাম, https লিংক ও যোগাযোগ দিন');
  const L=await rd(env,'ads',[]);if(L.length>=2000)return er('সীমা শেষ');
  L.unshift({...o,status:'pending',id:crypto.randomUUID(),createdAt:new Date().toISOString()});await wr(env,'ads',L);
  return J({ok:1,message:'অনুরোধ জমা হয়েছে, অনুমোদনের অপেক্ষায় আছে'})}
 if(p==='/api/login'&&m==='POST'){
  if(!await limit(env,'login:'+ip,8,600))return er('অনেকবার চেষ্টা হয়েছে। ১০ মিনিট পরে আবার চেষ্টা করুন।',429);
  const{password}=await req.json().catch(()=>({}));let h=await env.DB.get('admin_hash');
  if(!h&&env.ADMIN_PASSWORD){h=await hash(env.ADMIN_PASSWORD);await env.DB.put('admin_hash',h)}
  if(!h)return er('ADMIN_PASSWORD সেট করা নেই',500);
  if(!await verify(password,h)){await audit(env,ip,'ভুল পাসওয়ার্ডে লগইন চেষ্টা');return er('পাসওয়ার্ড ভুল',401)}
  await audit(env,ip,'লগইন');return J({ok:1},200,{'set-cookie':await cookie(env)})}
 if(p==='/api/logout')return J({ok:1},200,{'set-cookie':'ih_s=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'});
 const tk=(req.headers.get('cookie')||'').match(/ih_s=([^;]+)/);
 if(!await check(env,tk&&tk[1]))return er('লগইন করুন',401);
 if(m!=='GET'&&req.headers.get('x-ih')!=='1')return er('অনুমোদিত নয়',403);
 const r=await admin(req,env,p,m,ip);r.headers.append('set-cookie',await cookie(env));return r}
async function admin(req,env,p,m,ip){
 const s=p.split('/').filter(Boolean),c=s[2],id=s[3],b=()=>req.json().catch(()=>({}));
 if(c==='me')return J({ok:1});
 if(c==='audit')return J(await rd(env,'audit',[]));
 if(c==='settings'){if(m==='PUT'){const o=clean(await b());await wr(env,'settings',o);await audit(env,ip,'সেটিংস পরিবর্তন');return J(o)}return J({...DEF,...await rd(env,'settings',{})})}
 if(c==='backup'){const o={settings:await rd(env,'settings',DEF)};for(const k of COLS)o[k]=await rd(env,k,[]);return J(o)}
 if(c==='restore'&&m==='POST'){const o=await b();for(const k of COLS)if(!Array.isArray(o[k]))return er('ব্যাকআপ ফাইল সঠিক নয়');
  for(const k of COLS)await wr(env,k,o[k].slice(0,2000).map(x=>({...clean(x),id:String(x.id||crypto.randomUUID()).slice(0,60),createdAt:String(x.createdAt||'').slice(0,30),updatedAt:String(x.updatedAt||'').slice(0,30)})));
  if(o.settings)await wr(env,'settings',clean(o.settings));await audit(env,ip,'ব্যাকআপ পুনরুদ্ধার');return J({ok:1})}
 if(c==='password'&&m==='POST'){const{old,nw}=await b();if(typeof nw!=='string'||nw.length<10)return er('নতুন পাসওয়ার্ড কমপক্ষে ১০ অক্ষরের হতে হবে');
  if(!await verify(old,await env.DB.get('admin_hash')))return er('পুরনো পাসওয়ার্ড ভুল',403);
  await env.DB.put('admin_hash',await hash(nw));await audit(env,ip,'পাসওয়ার্ড পরিবর্তন');return J({ok:1})}
 if(!COLS.includes(c))return er('পাওয়া যায়নি',404);
 const L=await rd(env,c,[]),now=new Date().toISOString(),dup=o=>{if(c==='articles'&&o.slug&&L.some(x=>x.slug===o.slug&&x.id!==o.id))throw new Error('!এই slug আগে থেকেই আছে')};
 if(!id&&m==='GET')return J(L);
 if(!id&&m==='POST'){if(L.length>=2000)return er('সীমা শেষ');const o={...clean(await b()),id:crypto.randomUUID(),createdAt:now,updatedAt:now};dup(o);L.unshift(o);await wr(env,c,L);await audit(env,ip,c+' যোগ');return J(o)}
 const i=L.findIndex(x=>x.id===id);if(i<0)return er('পাওয়া যায়নি',404);
 if(m==='DELETE'){L.splice(i,1);await wr(env,c,L);await audit(env,ip,c+' মোছা');return J({ok:1})}
 if(m==='PUT'){const o={...L[i],...clean(await b()),updatedAt:now};dup(o);L[i]=o;await wr(env,c,L);await audit(env,ip,c+' পরিবর্তন');return J(o)}
 if(m==='POST'&&s[4]==='action'&&c==='users'){const a=await b(),u=L[i],pl=['pro','elite'].includes(a.plan)?a.plan:'pro',d=Math.min(Math.max(Math.floor(+a.days)||30,1),3650),f=x=>new Date(x).toISOString().slice(0,10);
  if(a.type==='grant'){u.plan=pl;u.expires=f(Date.now()+d*DAY)}
  else if(a.type==='lifetime'){u.plan=pl;u.expires='lifetime'}
  else if(a.type==='extend'){if(u.expires!=='lifetime'){const t=u.expires&&new Date(u.expires)>new Date()?new Date(u.expires).getTime():Date.now();u.expires=f(t+d*DAY)}}
  else if(a.type==='remove'){u.plan='starter';u.expires=''}
  else return er('অজানা কাজ');
  u.updatedAt=now;await wr(env,c,L);await audit(env,ip,'সদস্য '+a.type);return J(u)}
 return er('পাওয়া যায়নি',404)}
