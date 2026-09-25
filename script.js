(function(){
'use strict';
var D=window.IH_DATA,CATS=D.categories,ARTS=D.articles,app=document.getElementById('app'),bar=document.getElementById('progress');
var esc=function(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})};
var store={get:function(k,d){try{var v=JSON.parse(localStorage.getItem(k));return v==null?d:v}catch(e){return d}},set:function(k,v){try{localStorage.setItem(k,JSON.stringify(v))}catch(e){}}};
var ADS=[],AFF=[],PRD=[],BIZ=[],JOB=[],SET={proPrice:'149',elitePrice:'499',bkash:'',bank:'',bankAccount:'',holder:'',swift:''},bm=store.get('ih-bm',[]),st={cat:'all',q:''};
var catName=function(id){var c=CATS.filter(function(x){return x.id===id})[0];return c?c.name:''};
function theme(t){document.documentElement.dataset.theme=t;store.set('ih-theme',t)}
theme(store.get('ih-theme',matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'));
document.getElementById('theme').onclick=function(){theme(document.documentElement.dataset.theme==='dark'?'light':'dark')};

function card(a){return '<a class="card glass" href="#/a/'+a.slug+'"><span class="meta">'+esc(catName(a.cat))+'</span><h3>'+esc(a.title)+'</h3><p>'+esc(a.summary)+'</p></a>'}
function list(){
  var q=st.q.trim().toLowerCase();
  var r=ARTS.filter(function(a){
    if(st.cat==='saved'&&bm.indexOf(a.slug)<0)return false;
    if(st.cat!=='all'&&st.cat!=='saved'&&a.cat!==st.cat)return false;
    return !q||(a.title+' '+a.summary+' '+a.tags.join(' ')+' '+catName(a.cat)).toLowerCase().indexOf(q)>-1});
  document.getElementById('grid').innerHTML=r.length?r.map(card).join(''):'<p class="empty">কিছু পাওয়া যায়নি। অন্য শব্দ দিয়ে খুঁজুন।</p>';
}
function chips(){
  var all=[{id:'all',name:'সব'}].concat(CATS,[{id:'saved',name:'সংরক্ষিত ('+bm.length+')'}]);
  document.getElementById('chips').innerHTML=all.map(function(c){return '<button class="btn" type="button" data-c="'+c.id+'" aria-pressed="'+(st.cat===c.id)+'">'+esc(c.name)+'</button>'}).join('');
}
function showAds(){var e=document.getElementById('ads');if(e&&ADS.length)e.innerHTML=ADS.map(function(a){return '<a class="card glass" href="'+esc(a.url)+'" target="_blank" rel="noopener sponsored"><span class="meta">বিজ্ঞাপন</span><h3>'+esc(a.title)+'</h3><p>'+esc(a.text||'')+'</p></a>'}).join('')}
function home(){
  document.title='InfoHub Max — জানুন, বুঝুন, খুঁজে নিন।';
  app.innerHTML='<section class="hero"><h1>জানুন, বুঝুন, খুঁজে নিন।</h1><p>যাচাই করা উত্তর, সহজ বাংলায়।</p><input id="q" class="search" type="search" placeholder="আপনার প্রশ্ন লিখুন..." aria-label="খুঁজুন" value="'+esc(st.q)+'"></section><div id="chips" class="chips"></div><div id="grid" class="grid"></div><div id="ads" class="grid"></div>';
  chips();list();showAds();
  document.getElementById('q').oninput=function(e){st.q=e.target.value;list()};
  document.getElementById('chips').onclick=function(e){var c=e.target.getAttribute('data-c');if(c){st.cat=c;chips();list()}};
}
function article(a){
  document.title=a.title+' — InfoHub Max';
  var rel=ARTS.filter(function(x){return x.slug!==a.slug&&(x.cat===a.cat||x.tags.some(function(t){return a.tags.indexOf(t)>-1}))}).slice(0,3);
  var body=a.body.map(function(b){return b[0]==='h'?'<h2>'+esc(b[1])+'</h2>':'<p>'+esc(b[1])+'</p>'}).join('');
  var saved=bm.indexOf(a.slug)>-1;
  app.innerHTML='<article><a href="#/">← সব লেখা</a><p class="meta">'+esc(catName(a.cat))+' • হালনাগাদ: '+esc(a.updated)+'</p><h1>'+esc(a.title)+'</h1><p class="lead glass">'+esc(a.summary)+'</p><div class="tools"><button id="listen" class="btn" type="button" aria-pressed="false">শুনুন</button><button id="share" class="btn" type="button">শেয়ার</button><button id="save" class="btn" type="button" aria-pressed="'+saved+'">'+(saved?'সংরক্ষিত':'সংরক্ষণ')+'</button></div>'+body+'<h2>সাধারণ প্রশ্ন</h2>'+a.faq.map(function(f){return '<details class="glass"><summary>'+esc(f[0])+'</summary><p>'+esc(f[1])+'</p></details>'}).join('')+'<h2>সূত্র</h2><ul class="src">'+a.sources.map(function(s){return '<li>'+esc(s)+'</li>'}).join('')+'</ul><p class="note">নমুনা লেখা: প্রকাশের আগে সূত্র মিলিয়ে দেখুন।</p>'+(rel.length?'<h2>সম্পর্কিত লেখা</h2><div class="grid">'+rel.map(card).join('')+'</div>':'')+'</article>';
  var old=document.getElementById('ld');if(old)old.remove();
  var ld=document.createElement('script');ld.type='application/ld+json';ld.id='ld';
  ld.textContent=JSON.stringify({'@context':'https://schema.org','@type':'Article',headline:a.title,inLanguage:'bn',description:a.summary});
  document.head.appendChild(ld);
  document.getElementById('save').onclick=function(){var i=bm.indexOf(a.slug);if(i>-1)bm.splice(i,1);else bm.push(a.slug);store.set('ih-bm',bm);article(a)};
  document.getElementById('share').onclick=function(){var d={title:a.title,url:location.href};if(navigator.share)navigator.share(d).catch(function(){});else if(navigator.clipboard)navigator.clipboard.writeText(d.url).then(function(){document.getElementById('share').textContent='লিংক কপি হয়েছে'})};
  var L=document.getElementById('listen');
  L.onclick=function(){
    if(!('speechSynthesis' in window)){L.textContent='এই ব্রাউজারে সমর্থিত নয়';return}
    if(speechSynthesis.speaking){speechSynthesis.cancel();L.setAttribute('aria-pressed','false');L.textContent='শুনুন';return}
    var u=new SpeechSynthesisUtterance(a.title+'। '+a.body.map(function(b){return b[1]}).join('। '));u.lang='bn-BD';
    u.onend=function(){L.setAttribute('aria-pressed','false');L.textContent='শুনুন'};
    speechSynthesis.speak(u);L.setAttribute('aria-pressed','true');L.textContent='থামান';
  };
}
function pricing(){
  document.title='মূল্য পরিকল্পনা — InfoHub Max';
  var plans=[['Starter','বিনামূল্যে',['মৌলিক লেখা পড়ুন','সংরক্ষণ ও শেয়ার']],
   ['Pro','৳'+esc(SET.proPrice)+' / মাস',['Starter-এর সবকিছু','বিজ্ঞাপনমুক্ত পড়া (পরিকল্পিত)']],
   ['Max Elite','৳'+esc(SET.elitePrice)+' / মাস',['Pro-এর সবকিছু','অগ্রাধিকার সহায়তা (পরিকল্পিত)']]];
  app.innerHTML='<section class="hero"><h1>মূল্য পরিকল্পনা</h1><p>আপনার প্রয়োজন অনুযায়ী বেছে নিন।</p></section><div class="grid">'+
   plans.map(function(p){return '<div class="card glass"><h3>'+p[0]+'</h3><p class="meta">'+p[1]+'</p><ul>'+p[2].map(function(f){return '<li>'+f+'</li>'}).join('')+'</ul></div>'}).join('')+
   '</div><div class="lead glass" style="margin-top:16px"><h2>পেমেন্ট তথ্য</h2><p>bKash: '+esc(SET.bkash||'শীঘ্রই যোগ হবে')+'</p><p>ব্যাংক: '+esc(SET.bank||'-')+(SET.bankAccount?' — হিসাব নম্বর: '+esc(SET.bankAccount):'')+(SET.holder?' — হিসাবধারী: '+esc(SET.holder):'')+(SET.swift?' — SWIFT: '+esc(SET.swift):'')+'</p><p class="note">সদস্যপদ সক্রিয় করতে পেমেন্টের পর অ্যাডমিনের সঙ্গে যোগাযোগ করুন।</p></div>';
}
function adPage(){
  document.title='বিজ্ঞাপন দিন — InfoHub Max';
  app.innerHTML='<section class="hero"><h1>বিজ্ঞাপন দিন</h1><p>প্রতিটি বিজ্ঞাপন প্রকাশের আগে অ্যাডমিন যাচাই করে অনুমোদন করেন।</p></section>'+
   '<form id="adform" class="glass box" style="padding:18px;max-width:560px;margin:auto"><label>শিরোনাম<br><input id="af-title" required style="width:100%;padding:8px"></label><br><br>'+
   '<label>লিংক (https দিয়ে শুরু)<br><input id="af-url" type="url" required placeholder="https://" style="width:100%;padding:8px"></label><br><br>'+
   '<label>বিবরণ<br><textarea id="af-text" rows="4" style="width:100%;padding:8px"></textarea></label><br><br>'+
   '<label>যোগাযোগ (ফোন/ইমেইল)<br><input id="af-contact" required style="width:100%;padding:8px"></label><br><br>'+
   '<button class="btn" type="submit">অনুরোধ পাঠান</button><p id="af-msg" role="status"></p></form>';
  document.getElementById('adform').onsubmit=function(e){
    e.preventDefault();var m=document.getElementById('af-msg');m.textContent='পাঠানো হচ্ছে...';
    fetch('/api/public/ad-request',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({title:document.getElementById('af-title').value,url:document.getElementById('af-url').value,text:document.getElementById('af-text').value,contact:document.getElementById('af-contact').value})})
    .then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d}})})
    .then(function(x){m.textContent=x.ok?x.d.message:(x.d.error||'ত্রুটি হয়েছে')})
    .catch(function(){m.textContent='সংযোগ ব্যর্থ হয়েছে, পরে চেষ্টা করুন।'});
  };
}
function listPage(title,items,render){
  document.title=title+' — InfoHub Max';
  app.innerHTML='<section class="hero"><h1>'+title+'</h1></section><div class="grid">'+
   (items.length?items.map(render).join(''):'<p class="empty">এখনো কিছু যোগ হয়নি।</p>')+'</div>';
}
function affiliatesPage(){listPage('অ্যাফিলিয়েট লিংক',AFF,function(x){return '<a class="card glass" href="'+esc(x.url||'#')+'" target="_blank" rel="noopener nofollow sponsored"><h3>'+esc(x.name)+'</h3><p class="meta">কমিশন: '+esc(x.commission||'-')+'</p></a>'})}
function productsPage(){listPage('ডিজিটাল পণ্য',PRD,function(x){return '<a class="card glass" href="'+esc(x.url||'#')+'" target="_blank" rel="noopener"><h3>'+esc(x.title)+'</h3><p class="meta">৳'+esc(x.price||'-')+'</p></a>'})}
function directoryPage(){listPage('ব্যবসা ডিরেক্টরি',BIZ,function(x){return '<div class="card glass"><h3>'+esc(x.name)+'</h3><p>'+esc(x.address||'')+'</p><p class="meta">'+esc(x.phone||'')+(x.url?' • <a href="'+esc(x.url)+'" target="_blank" rel="noopener">ওয়েবসাইট</a>':'')+'</p></div>'})}
function jobsPage(){listPage('চাকরির খবর',JOB,function(x){return '<a class="card glass" href="'+esc(x.url||'#')+'" target="_blank" rel="noopener"><h3>'+esc(x.title)+'</h3><p class="meta">'+esc(x.company||'')+'</p></a>'})}
function route(){
  if('speechSynthesis' in window)speechSynthesis.cancel();
  var o=document.getElementById('ld');if(o)o.remove();
  var h=location.hash;
  if(h==='#/pricing'){pricing();window.scrollTo(0,0);bar.style.width='0';return}
  if(h==='#/ad'){adPage();window.scrollTo(0,0);bar.style.width='0';return}
  var pages={'#/affiliates':affiliatesPage,'#/products':productsPage,'#/directory':directoryPage,'#/jobs':jobsPage};
  if(pages[h]){pages[h]();window.scrollTo(0,0);bar.style.width='0';return}
  var m=h.match(/^#\/a\/(.+)$/),a=m&&ARTS.filter(function(x){return x.slug===m[1]})[0];
  if(a)article(a);else home();
  window.scrollTo(0,0);bar.style.width='0';
}
addEventListener('hashchange',route);
addEventListener('scroll',function(){var h=document.documentElement,t=h.scrollHeight-h.clientHeight;bar.style.width=(t>0?h.scrollTop/t*100:0)+'%'},{passive:true});
fetch('/api/public/data').then(function(r){return r.ok?r.json():null}).then(function(d){if(!d)return;ADS=d.ads||[];if(d.articles&&d.articles.length){ARTS.length=0;d.articles.forEach(function(a){ARTS.push(a)});if(d.categories&&d.categories.length){CATS.length=0;d.categories.forEach(function(c){CATS.push(c)})}}if(d.settings)SET=d.settings;AFF=d.affiliates||[];PRD=d.products||[];BIZ=d.businesses||[];JOB=d.jobs||[];}).catch(function(){}).then(function(){route()});
if('serviceWorker' in navigator)addEventListener('load',function(){navigator.serviceWorker.register('sw.js').catch(function(){})});
})();
