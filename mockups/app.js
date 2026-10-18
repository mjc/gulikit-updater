const $ = (id) => document.getElementById(id);
const previewQuery = new URLSearchParams(globalThis.location?.search || '');
const initialState = previewQuery.get('state');
let state = ['connect','ready','writing','reconnect','complete','error'].includes(initialState) ? initialState : 'ready';
let component = previewQuery.get('component') === 'main' ? 'main' : 'bt';
let view = 'desktop';
let wrongFile = false;
let timer;
let progress = 0;
let switchingMode = false;
const firmwareByComponent = {
  bt: {name:'Bluetooth firmware',current:'5.06',target:'5.07',file:'GuliKit_NS38_NS39_NS59_BT_V5.07.zip',size:'345,088 bytes',payloadBytes:345088,mode:'Gear / Set',button:'gear',hash:'2e0e89d4…3441826'},
  main: {name:'Main firmware',current:'5.8',target:'5.9',file:'NS39_KK3_MAX_V5.9.bin',size:'51,500 bytes',payloadBytes:51500,mode:'APS (double-square)',button:'aps',hash:'d1c7d485…6d6ae4'},
};
const info = () => firmwareByComponent[component];
const transferPending = () => state==='writing' || state==='reconnect';
const notice = (text, warning = false) => `<div class="notice ${warning?'warning':''}"><span class="notice-icon">${warning?'!':'ⓘ'}</span><p>${text}</p></div>`;
const btn = (id, text, disabled = false) => `<button id="${id}" class="primary" ${disabled?'disabled':''}>${text}</button>`;
const buttonSymbol = (button, description) => `<img src="icons/${button}.svg" width="24" height="24" alt="${description}">`;
const rightmostA = () => `<span class="button-instruction"><span>Use the rightmost</span>${buttonSymbol('a','A')}<span>button (default Switch layout).</span></span>`;
const modeKeys = (d, keepHeld = false) => `<span class="button-instruction"><span>${keepHeld?'Keep':'Hold'}</span><span class="button-name">${buttonSymbol(d.button,d.button==='gear'?'Gear / Set button':'APS button (overlapping squares)')}<strong>${d.button==='gear'?'Gear':'APS'}</strong></span><span>${keepHeld?'held while pressing':'first, then press'}</span>${buttonSymbol('a','A button (rightmost in default Switch layout)')}</span>`;
const entrySteps = () => `<ol class="steps">${switchingMode?'<li><span>Hold Mode to turn off, then turn on normally.</span></li>':''}<li><span>Turn off. Connect a USB data cable.</span></li><li><span>${modeKeys(info())}<small class="button-hint">${modeKeys(info(),true)}</small><small class="button-hint">${rightmostA()}</small></span></li></ol>`;
function selectComponent(next){
  if(next===component || !['main','bt'].includes(next) || transferPending()) return;
  component=next;
  switchingMode=true;
  setState('connect');
}
function render(){
  renderSelectors();
  renderDeviceStatus();
  renderScreen(info());
  bindScreenActions();
}
function renderSelectors(){
  document.querySelectorAll('[data-state]').forEach(b => {
    b.classList.toggle('active',b.dataset.state===state);
    b.setAttribute('aria-pressed',String(b.dataset.state===state));
  });
  document.querySelectorAll('[data-component]').forEach(b => {
    b.classList.toggle('selected',b.dataset.component===component);
    b.setAttribute('aria-pressed',String(b.dataset.component===component));
    b.disabled=transferPending();
  });
}
function observedVersion(expectedComponent){
  if(component!==expectedComponent || state==='connect' || state==='error') return 'Version unknown';
  const firmware=info();
  return state==='complete'?firmware.target:firmware.current;
}
function renderDeviceStatus(){
  document.querySelector('.app-window').classList.toggle('disconnected',state==='connect');
  document.querySelector('.app-window').classList.toggle('error-state',state==='error');
  document.querySelector('.device-label').innerHTML=`${state==='connect'||state==='error'?'EXPECTED CONTROLLER':'CONTROLLER'} <span class="connection-dot"></span>`;
  $('bt-version').textContent=observedVersion('bt');
  $('main-version').textContent=observedVersion('main');
  $('connection-badge').textContent=state==='connect'?'Not connected':state==='reconnect'?'Restart pending':state==='error'?'Unidentified USB device':'USB connected';
}
function renderScreen(d){
  let title, body, action, footer;
  if(state==='connect'){
    title='Connect controller';
    body=`${entrySteps()}${view==='android'?notice('Allow USB access when Android asks.'):''}`;
    action=`<button class="quiet" id="reconnect-help">Connection help</button>${btn('simulate-connect','Simulate inspection <span>→</span>')}`;
    footer='Waiting for USB';
  } else if(state==='ready'){
    title=d.name;
    body=`<div class="package"><div class="version-row"><div class="version-col"><label>INSTALLED</label><strong>${d.current}</strong></div><span class="version-arrow">→</span><div class="version-col"><label>SELECTED</label><strong>${wrongFile?'5.8':d.target}</strong></div></div><div class="selected-file"><span class="file-icon">▤</span><span>${wrongFile?'NS38_KK3_PRO_V5.8.bin':d.file}</span></div></div>${wrongFile?notice('Wrong model. Choose an NS39 package.',true):notice(component==='bt'?'Simulation only · Bluetooth hardware updates are not available yet.':'Simulated transfer · no firmware is written.')}<details class="details" id="details"><summary>Package details</summary><dl class="package-details"><dt>Model</dt><dd>${wrongFile?'KK3 Pro · NS38':'KK3 Max · NS39'}</dd><dt>Payload</dt><dd>${wrongFile?'51,624 bytes':d.size}</dd><dt>SHA-256</dt><dd>${wrongFile?'433ae3fc…a934a30':d.hash}</dd></dl></details>`;
    action=`<button class="quiet" id="choose-file">Choose file…</button>${btn('start-update','Update to '+(wrongFile?'5.8':d.target)+' <span>→</span>',wrongFile)}`;
    footer=wrongFile?'Update blocked':'Identity confirmed';
  } else if(state==='writing'){
    title='Updating…';
    body=`<div class="progress-card"><div class="progress-heading"><strong>${d.name} ${d.target}</strong><span id="percent">${progress}%</span></div><div id="progress-track" class="progress-track" role="progressbar" aria-label="Firmware transfer" aria-valuenow="${progress}" aria-valuemin="0" aria-valuemax="100"><div id="progress-fill" class="progress-fill" style="width:${progress}%"></div></div><div class="progress-meta"><span id="progress-bytes">${Math.round(d.payloadBytes*progress/100).toLocaleString()} / ${d.size}</span></div><div class="transfer-stages"><div class="done"><span class="state-icon">✓</span> Package checked</div><div class="current"><span class="state-icon">◉</span> Writing firmware</div><div class="pending"><span class="state-icon">○</span> Restart & verify</div></div></div>${notice('Keep USB connected.')}`;
    action='';
    footer='Writing firmware';
  } else if(state==='reconnect'){
    title=component==='bt'?'Restart controller':'Start controller normally';
    body=`<div class="restart-icon">↻</div><p class="short-copy">${component==='bt'?'After completion, power off and on normally.':'Wait for the controller to power off automatically and for the GuliKit drive to disappear. Then turn on normally.'}</p><p class="short-copy">For fresh readback, turn off and re-enter this component’s update mode:</p><div class="mode-prompt">${modeKeys(d)}</div><p class="button-hint">${modeKeys(d,true)}</p><p class="button-hint">${rightmostA()}</p>`;
    action=`<button class="quiet" id="reconnect-help">Connection help</button>${btn('simulate-restart','Simulate fresh readback <span>→</span>')}`;
    footer='Transfer complete · verification pending';
  } else if(state==='complete'){
    title='Update verified';
    body=`<div class="success-icon">✓</div><div class="result-card"><div><strong>${d.name}</strong><small>Confirmed after restart</small></div><span class="result-version">${d.target}</span></div><p class="short-copy">You can disconnect.</p>`;
    action=`<button class="quiet" id="save-summary">Copy summary</button>${btn('other-component',(component==='bt'?'Main':'Bluetooth')+' firmware <span>→</span>')}`;
    footer='Installed version verified';
  } else {
    title='Controller not identified';
    body=`<div class="error-icon">!</div><p class="short-copy">Identity request timed out. No firmware written.</p><ol class="steps"><li><span>Reconnect the USB data cable.</span></li><li><span>Use update mode: ${modeKeys(d)}</span></li></ol>`;
    action=`<button class="quiet" id="error-log">View log</button>${btn('retry','Retry <span>↻</span>')}`;
    footer='Update blocked · identity unknown';
  }
  $('screen-title').textContent=title;
  $('screen-body').innerHTML=body;
  $('action-area').innerHTML=action;
  $('footer-status').innerHTML=`<i></i>${footer}`;
  $('log-text').textContent=`[demo] ${d.name}\n`+(state==='error'?`Selected mode: ${d.mode} + A\nIdentity read: failed (simulated)\nFirmware writes: blocked`:state==='complete'?`Model: NS39\nTransfer: complete\nVersion after restart: ${d.target}`:`Model: NS39 (simulated)\nPackage: ${d.file}\n${footer}`);
}
function bindScreenActions(){
  bind('simulate-connect',()=>{switchingMode=false;setState('ready')});
  bind('start-update',startDemo);
  bind('simulate-restart',()=>setState('complete'));
  bind('retry',()=>setState('connect'));
  bind('other-component',()=>selectComponent(component==='bt'?'main':'bt'));
  bind('reconnect-help',()=> $('help-dialog').showModal());
  bind('error-log',()=>{$('log-panel').hidden=false});
  bind('choose-file',showFileChooser);
  bind('save-summary',async()=>{await copyText($('log-text').textContent);$('save-summary').textContent='Copied'});
}
function bind(id,fn){$(id)?.addEventListener('click',fn)}
function setState(next, initialProgress = next==='writing'?64:0){clearInterval(timer);clearTimeout(timer);state=next;wrongFile=false;progress=initialProgress;render()}
function startDemo(){
  const d=info();
  const total=d.payloadBytes;
  setState('writing',0);
  timer=setInterval(()=>{
    progress=Math.min(progress+4,100);
    $('percent').textContent=`${progress}%`;
    $('progress-track').setAttribute('aria-valuenow',String(progress));
    $('progress-fill').style.width=`${progress}%`;
    $('progress-bytes').textContent=`${Math.round(total*progress/100).toLocaleString()} / ${d.size}`;
    if(progress===100){clearInterval(timer);timer=setTimeout(()=>setState('reconnect'),600)}
  },220);
}
function showFileChooser(){
  const dialog=document.createElement('dialog');
  dialog.innerHTML=`<form method="dialog"><button class="dialog-close" aria-label="Close file picker">×</button><h2>Choose file</h2><p>Sample files</p><div class="sample-files"><button value="correct" class="secondary">${info().file}</button><button value="wrong" class="secondary">NS38_KK3_PRO_V5.8.bin · wrong model</button></div></form>`;
  document.body.append(dialog);
  dialog.addEventListener('close',()=>{
    if(dialog.returnValue==='correct'||dialog.returnValue==='wrong'){wrongFile=dialog.returnValue==='wrong';render()}
    dialog.remove();
  });
  dialog.showModal();
}
async function copyText(text){
  try{await navigator.clipboard.writeText(text)}
  catch{const t=document.createElement('textarea');t.value=text;document.body.append(t);t.select();document.execCommand('copy');t.remove()}
}
document.querySelectorAll('[data-state]').forEach(b=>b.addEventListener('click',()=>setState(b.dataset.state)));
document.querySelectorAll('[data-component]').forEach(b=>b.addEventListener('click',()=>selectComponent(b.dataset.component)));
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>{
  view=b.dataset.view;document.body.classList.toggle('android',view==='android');
  document.querySelectorAll('[data-view]').forEach(x=>{x.classList.toggle('active',x===b);x.setAttribute('aria-pressed',String(x===b))});
  $('platform-note').textContent=view==='android'?'Android concept · iOS deferred':'Windows / macOS / Linux';render();
}));
bind('activity',()=>{$('log-panel').hidden=!$('log-panel').hidden});
bind('close-log',()=>{$('log-panel').hidden=true});
bind('copy-log',async()=>{await copyText($('log-text').textContent);$('copy-log').textContent='Copied';setTimeout(()=>$('copy-log').textContent='Copy',1500)});
bind('help',()=> $('help-dialog').showModal());
render();
