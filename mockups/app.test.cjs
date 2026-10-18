const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

// Run the production callbacks with a small DOM adapter, without a browser or desktop.
function mockup(search = '') {
  const elements = new Map();
  const timers = new Map();
  let timerId = 0;
  function element(id, dataset = {}) {
    const listeners = new Map();
    let html = '';
    const children = [];
    const item = {
      dataset, disabled: false, hidden: true, textContent: '', style: {}, attributes: {}, htmlWrites: 0,
      classList: { toggle() {} },
      setAttribute(name, value) { this.attributes[name] = value; },
      addEventListener(name, callback) { listeners.set(name, callback); },
      click() { if (!this.disabled) listeners.get('click')?.(); },
      showModal() { this.hidden = false; },
      get innerHTML() { return html; },
      set innerHTML(value) {
        this.htmlWrites++;
        for (const child of children) elements.delete(child);
        children.length = 0;
        html = value;
        for (const match of value.matchAll(/<[\w-]+\b([^>]*)>/g)) {
          const childId = match[1].match(/\bid="([^"]+)"/)?.[1];
          if (childId) { const child = element(childId); child.disabled = /\bdisabled\b/.test(match[1]); children.push(childId); }
        }
      },
    };
    elements.set(id, item);
    return item;
  }
  const states = ['connect', 'ready', 'writing', 'reconnect', 'complete', 'error'].map(state => element(`state-${state}`, { state }));
  const components = ['main', 'bt'].map(component => element(`component-${component}`, { component }));
  const views = ['desktop', 'android'].map(view => element(`view-${view}`, { view }));
  for (const id of ['app-window', 'device-label', 'bt-version', 'main-version', 'connection-badge', 'screen-title', 'screen-body', 'action-area', 'footer-status', 'log-text', 'help-dialog', 'log-panel', 'activity', 'close-log', 'copy-log', 'help', 'platform-note']) element(id);
  elements.get('help-dialog').innerHTML = readFileSync(join(__dirname, 'index.html'), 'utf8').split('<dialog id="help-dialog">')[1].split('</dialog>')[0];
  const document = {
    getElementById(id) { return elements.get(id); },
    querySelector(selector) { return elements.get(selector.slice(1)); },
    querySelectorAll(selector) { return { '[data-state]': states, '[data-component]': components, '[data-view]': views }[selector] || []; },
    body: { classList: { toggle() {} } },
  };
  const context = vm.createContext({ document, URLSearchParams, location: { search }, setInterval(callback) { timers.set(++timerId, callback); return timerId; }, setTimeout(callback) { timers.set(++timerId, callback); return timerId; }, clearInterval(id) { timers.delete(id); }, clearTimeout(id) { timers.delete(id); } });
  vm.runInContext(readFileSync(join(__dirname, 'app.js'), 'utf8'), context);
  return {
    click(id) { assert.ok(elements.has(id), `missing control ${id}`); elements.get(id).click(); },
    get state() { return vm.runInContext('state', context); },
    get component() { return vm.runInContext('component', context); },
    get body() { return elements.get('screen-body').innerHTML; },
    get help() { return elements.get('help-dialog').innerHTML; },
    text(id) { return elements.get(id).textContent; },
    element(id) { return elements.get(id); },
    timers,
  };
}

test('both component buttons require mode exit, new entry instructions and explicit inspection', () => {
  const app = mockup();
  for (const component of ['main', 'bt']) {
    app.click(`component-${component}`);
    assert.equal(app.component, component);
    assert.equal(app.state, 'connect', 'component selection cannot claim a ready attachment');
    assert.match(app.body, /Mode.*off/i);
    assert.match(app.body, /normal/i);
    assert.equal(app.text('main-version'), 'Version unknown');
    assert.equal(app.text('bt-version'), 'Version unknown');
    app.click('simulate-connect');
    assert.equal(app.state, 'ready');
    assert.equal(app.text(component === 'main' ? 'bt-version' : 'main-version'), 'Version unknown', 'the other mode cannot inherit a live observation');
  }
});

test('each preview state reports only the selected component observation', () => {
  for (const component of ['main', 'bt']) {
    const current = component === 'main' ? '5.8' : '5.06';
    const target = component === 'main' ? '5.9' : '5.07';
    for (const state of ['connect', 'ready', 'writing', 'reconnect', 'complete', 'error']) {
      const app = mockup(`?component=${component}&state=${state}`);
      const expected = ['connect', 'error'].includes(state) ? 'Version unknown' : state === 'complete' ? target : current;
      assert.equal(app.text(`${component}-version`), expected, `${component} in ${state}`);
      assert.equal(app.text(`${component === 'main' ? 'bt' : 'main'}-version`), 'Version unknown');
    }
  }
});

test('progress updates retain the screen and controls until the delayed restart transition', () => {
  for (const component of ['main', 'bt']) {
    const app = mockup(`?component=${component}`);
    app.click('start-update');
    const total = component === 'main' ? 51500 : 345088;
    const body = app.element('screen-body');
    const writes = body.htmlWrites;
    const track = app.element('progress-track');
    const activity = app.element('activity');
    const log = app.text('log-text');
    assert.match(app.body, /aria-valuenow="0"/);
    for (let progress = 4; progress <= 100; progress += 4) {
      app.timers.values().next().value();
      assert.equal(app.state, 'writing');
      assert.equal(app.text('percent'), `${progress}%`);
      assert.equal(track.attributes['aria-valuenow'], String(progress));
      assert.equal(app.element('progress-fill').style.width, `${progress}%`);
      assert.equal(app.text('progress-bytes'), `${Math.round(total * progress / 100).toLocaleString()} / ${total.toLocaleString()} bytes`);
      assert.equal(body.htmlWrites, writes);
      assert.equal(app.element('progress-track'), track);
      assert.equal(app.element('activity'), activity);
      assert.equal(app.text('log-text'), log);
    }
    assert.equal(app.timers.size, 1, 'completion keeps a delayed restart callback');
    app.timers.values().next().value();
    assert.equal(app.state, 'reconnect');
    assert.equal(app.element('progress-track'), undefined);
  }
});

test('the verified other-firmware action also routes through mode instructions', () => {
  const app = mockup();
  app.click('state-complete');
  app.click('other-component');
  assert.equal(app.component, 'main');
  assert.equal(app.state, 'connect');
  assert.match(app.body, /APS/);
});

test('transfer and pending restart lock component switching', () => {
  const app = mockup();
  app.click('start-update');
  assert.equal(app.timers.size, 1);
  app.click('component-main');
  assert.equal(app.component, 'bt');
  assert.equal(app.state, 'writing');
  app.click('state-reconnect');
  assert.equal(app.timers.size, 0);
  app.click('component-main');
  assert.equal(app.component, 'bt');
  assert.equal(app.state, 'reconnect');
});

test('Bluetooth entry names Gear first and physical rightmost A in the default layout', () => {
  const app = mockup();
  app.click('state-connect');
  assert.match(app.body, /Gear.*first/i);
  assert.match(app.body, /Use the rightmost<\/span><img[^>]+src="icons\/a\.svg"/);
  assert.match(app.help, /APS/);
  assert.match(app.help, /Gear.*first/i);
});

test('Main automatic power-off and Bluetooth manual power cycle have different completion guidance', () => {
  const app = mockup();
  app.click('state-reconnect');
  assert.match(app.body, /power off.*on normally/i);
  app.click('state-complete'); app.click('other-component'); app.click('simulate-connect');
  app.click('state-reconnect');
  assert.match(app.body, /automatically/i);
  assert.match(app.body, /GuliKit.*disappear/i);
  assert.match(app.body, /on normally/i);
});

test('the mockup does not present native Bluetooth writes as qualified', () => {
  const app = mockup();
  assert.match(app.body, /Simulation only.*Bluetooth hardware updates are not available yet/i);
});

test('entry and restart instructions display the selected physical button symbols in order', () => {
  const app = mockup();
  for (const component of ['bt', 'main']) {
    if (component === 'main') { app.click('state-complete'); app.click('other-component'); }
    else app.click('state-connect');
    const icon = component === 'bt' ? 'gear' : 'aps';
    const order = new RegExp(`icons/${icon}\\.svg[\\s\\S]*icons/a\\.svg`);
    assert.match(app.body, order, 'show the held button before A');
    app.click('simulate-connect'); app.click('state-reconnect');
    assert.match(app.body, order, 'fresh readback uses the same button symbols');
  }
  assert.match(app.help, /icons\/aps\.svg/);
  assert.match(app.help, /icons\/gear\.svg/);
});

test('preview links can open each component directly on its button instructions', () => {
  for (const [component, icon] of [['main', 'aps'], ['bt', 'gear']]) {
    const app = mockup(`?state=connect&component=${component}`);
    assert.equal(app.state, 'connect'); assert.equal(app.component, component);
    assert.match(app.body, new RegExp(`icons/${icon}\\.svg`));
  }
});

test('both modes keep the held-button and A symbols in their hold reminders', () => {
  for (const [component, icon] of [['main', 'aps'], ['bt', 'gear']]) {
    const app = mockup(`?state=connect&component=${component}`);
    const reminder = new RegExp(`Keep[\\s\\S]*icons/${icon}\\.svg[\\s\\S]*held while pressing[\\s\\S]*icons/a\\.svg`);
    assert.match(app.body, reminder, 'entry reminder identifies both physical buttons');
    const rightmost = /Use the rightmost<\/span>[\s\S]*icons\/a\.svg[\s\S]*button \(default Switch layout\)/;
    assert.match(app.body, rightmost, 'both modes identify the rightmost A with its icon');
    app.click('simulate-connect'); app.click('state-reconnect');
    assert.match(app.body, reminder, 'readback reminder identifies both physical buttons');
    assert.match(app.body, rightmost, 'readback keeps the rightmost A reminder');
    assert.match(app.help, reminder, 'help includes the same hold reminder');
  }
});
