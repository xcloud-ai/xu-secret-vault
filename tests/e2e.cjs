/* XU Secret Vault 0.1.1 — e2e / 安全加固负向测试（Node 原生 WebCrypto + Obsidian 桩） */
'use strict';

const fs = require('fs');
const path = require('path');
const Module = require('module');
const { webcrypto } = require('crypto');

const MAIN = path.join(__dirname, '..', 'main.js');
const VAULT_PATH = 'xu-secrets.enc';

const MASTER = 'MASTER-PASSWORD-DO-NOT-LEAK-789';
const SECRET_ONE = 'SECRET-ALPHA-DO-NOT-LEAK-123';
const SECRET_TWO = 'SECRET-BETA-DO-NOT-LEAK-456';
const SECRET_THREE = 'SECRET-GAMMA-DO-NOT-LEAK-000';

let assertions = 0;
const failures = [];

function ok(condition, message) {
  assertions += 1;
  if (condition) {
    console.log('PASS  ' + message);
  } else {
    failures.push(message);
    console.error('FAIL  ' + message);
  }
}

async function rejects(promise, needle, message) {
  try {
    await promise;
    ok(false, message + '（未抛出异常）');
  } catch (error) {
    ok(String(error && error.message).indexOf(needle) >= 0, message);
  }
}

async function waitFor(fn, label, timeout) {
  const limit = Date.now() + (timeout || 5000);
  while (Date.now() < limit) {
    if (fn()) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  ok(false, '等待超时：' + label);
  return false;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* ---------------- 极简 DOM 桩 ---------------- */

function makeEl(tag, options) {
  const opts = options || {};
  const el = {
    tagName: String(tag).toUpperCase(),
    children: [],
    parent: null,
    textContent: '',
    value: '',
    type: '',
    disabled: false,
    rows: 0,
    autocomplete: '',
    spellcheck: true,
    attributes: {},
    _classes: new Set(),
    _listeners: {},
  };
  if (opts.cls) String(opts.cls).split(/\s+/).filter(Boolean).forEach((name) => el._classes.add(name));
  if (opts.text !== undefined) el.textContent = String(opts.text);
  if (opts.type) el.type = opts.type;
  el.classList = {
    add: (name) => el._classes.add(name),
    remove: (name) => el._classes.delete(name),
    contains: (name) => el._classes.has(name),
    toggle: (name, force) => {
      if (force === undefined ? !el._classes.has(name) : force) el._classes.add(name);
      else el._classes.delete(name);
    },
  };
  el.createEl = (childTag, childOptions) => {
    const child = makeEl(childTag, childOptions);
    child.parent = el;
    el.children.push(child);
    return child;
  };
  el.createDiv = (childOptions) => el.createEl('div', childOptions);
  el.createSpan = (childOptions) => el.createEl('span', childOptions);
  el.empty = () => {
    el.children = [];
    el.textContent = '';
  };
  el.setText = (text) => {
    el.textContent = String(text);
    el.children = [];
  };
  el.addClass = (name) => el._classes.add(name);
  el.removeClass = (name) => el._classes.delete(name);
  el.toggleClass = (name, force) => el.classList.toggle(name, force);
  el.hasClass = (name) => el._classes.has(name);
  el.setAttribute = (name, value) => {
    el.attributes[name] = String(value);
  };
  el.getAttribute = (name) => el.attributes[name];
  el.addEventListener = (type, handler) => {
    if (!el._listeners[type]) el._listeners[type] = [];
    el._listeners[type].push(handler);
  };
  el.removeEventListener = (type, handler) => {
    const list = el._listeners[type];
    if (!list) return;
    const index = list.indexOf(handler);
    if (index >= 0) list.splice(index, 1);
  };
  el.fire = (type, event) => {
    const list = el._listeners[type] || [];
    for (const handler of list.slice()) handler(event || {});
  };
  el.click = () => el.fire('click', {});
  el.focus = () => {};
  el.setSelectionRange = () => {};
  el.querySelector = (selector) => findByClass(el, selector.replace(/^\./, ''));
  return el;
}

function findByClass(root, className) {
  if (root._classes && root._classes.has(className)) return root;
  for (const child of root.children) {
    const hit = findByClass(child, className);
    if (hit) return hit;
  }
  return null;
}

function findAll(root, predicate, out) {
  const list = out || [];
  if (predicate(root)) list.push(root);
  for (const child of root.children) findAll(child, predicate, list);
  return list;
}

function findButton(root, text) {
  const buttons = findAll(root, (el) => el.tagName === 'BUTTON' && String(el.textContent).trim() === text);
  return buttons[0] || null;
}

function textOf(root) {
  let out = String(root.textContent || '');
  if (root.value) out += ' ' + String(root.value);
  for (const child of root.children) out += ' ' + textOf(child);
  return out;
}

/* ---------------- Obsidian / app 桩 ---------------- */

const fileStore = new Map();
const createdDirs = new Set();
const leaves = [];
const notices = [];
let clipboard = '';
let clipboardReadFailure = false;
let writeBehavior = null; // null | 'throw-before' | 'throw-partial'
let activePlugin = null;

const app = {
  vault: {
    adapter: {
      exists: async (filePath) => fileStore.has(filePath) || createdDirs.has(filePath),
      read: async (filePath) => {
        if (!fileStore.has(filePath)) throw new Error('file not found: ' + filePath);
        return fileStore.get(filePath);
      },
      write: async (filePath, text) => {
        if (writeBehavior === 'throw-before') throw new Error('simulated disk failure');
        if (writeBehavior === 'throw-partial') {
          // 模拟"写到一半"：先把截断内容落盘，再抛错
          fileStore.set(filePath, String(text).slice(0, Math.max(0, String(text).length - 24)));
          throw new Error('simulated partial write');
        }
        fileStore.set(filePath, String(text));
      },
      rename: async (fromPath, toPath) => {
        if (!fileStore.has(fromPath)) throw new Error('rename source missing: ' + fromPath);
        fileStore.set(toPath, fileStore.get(fromPath));
        fileStore.delete(fromPath);
      },
      remove: async (filePath) => {
        fileStore.delete(filePath);
      },
      stat: async (filePath) =>
        fileStore.has(filePath) ? { size: Buffer.byteLength(fileStore.get(filePath), 'utf8') } : null,
      mkdir: async (dirPath) => {
        createdDirs.add(dirPath);
      },
    },
  },
  workspace: {
    onLayoutReady: (callback) => callback(),
    on: () => ({ unregister() {} }),
    getLeavesOfType: (type) =>
      leaves.filter(
        (leaf) =>
          leaf.view &&
          typeof leaf.view.getViewType === 'function' &&
          leaf.view.getViewType() === type
      ),
    revealLeaf: async (leaf) => leaf,
    ensureSideLeaf: async (type) => {
      const leaf = { app, view: null, setViewState: async () => {} };
      const factory = activePlugin.__viewFactories[type];
      leaf.view = factory(leaf);
      leaves.push(leaf);
      return leaf;
    },
    getRightLeaf: () => null,
  },
  metadataCache: {
    on: () => ({ unregister() {} }),
    getFileCache: () => null,
  },
  setting: {
    openTabById: () => {},
  },
};

// document / window 事件桩：用于伪造 visibilitychange / blur
function makeEventTarget() {
  return {
    _listeners: {},
    hidden: false,
    addEventListener(type, handler) {
      if (!this._listeners[type]) this._listeners[type] = [];
      this._listeners[type].push(handler);
    },
    removeEventListener(type, handler) {
      const list = this._listeners[type];
      if (!list) return;
      const index = list.indexOf(handler);
      if (index >= 0) list.splice(index, 1);
    },
    fire(type, event) {
      for (const handler of (this._listeners[type] || []).slice()) handler(event || {});
    },
  };
}
const documentStub = makeEventTarget();
const windowStub = makeEventTarget();

class ItemView {
  constructor(leaf) {
    this.leaf = leaf;
    this.app = (leaf && leaf.app) || app;
    this.containerEl = makeEl('div');
    this.contentEl = this.containerEl.createDiv({ cls: 'view-content' });
  }
  registerDomEvent(el, type, handler) {
    el.addEventListener(type, handler);
  }
}

class Modal {
  constructor(modalApp) {
    this.app = modalApp;
    this.contentEl = makeEl('div');
    this.titleEl = makeEl('div');
    this.isOpen = false;
  }
  open() {
    this.isOpen = true;
    this.onOpen();
  }
  close() {
    if (!this.isOpen) return;
    this.isOpen = false;
    this.onClose();
  }
}

class Notice {
  constructor(message) {
    notices.push(String(message));
  }
}

class PluginSettingTab {
  constructor(pluginApp, plugin) {
    this.app = pluginApp;
    this.plugin = plugin;
  }
  update() {}
}

class Setting {}

class Plugin {
  constructor(pluginApp, manifest) {
    this.app = pluginApp;
    this.manifest = manifest;
    this.__viewFactories = {};
    this.__commands = [];
    this.__savedData = [];
    this.__settingTab = null;
  }
  async loadData() {
    return {};
  }
  async saveData(data) {
    this.__savedData.push(JSON.parse(JSON.stringify(data)));
  }
  registerView(type, factory) {
    this.__viewFactories[type] = factory;
  }
  registerInterval(id) {
    return id;
  }
  registerEvent() {}
  registerDomEvent(el, type, handler) {
    el.addEventListener(type, handler);
  }
  addCommand(command) {
    this.__commands.push(command);
  }
  addSettingTab(tab) {
    this.__settingTab = tab;
  }
  addRibbonIcon() {}
  addStatusBarItem() {
    return makeEl('div');
  }
}

const obsidianStub = { ItemView, Modal, Notice, Plugin, PluginSettingTab, Setting };

/* ---------------- 加载 main.js（主 realm，桩替换 require） ---------------- */

Object.defineProperty(globalThis, 'navigator', {
  value: {
    clipboard: {
      writeText: async (text) => {
        clipboard = String(text);
      },
      readText: async () => {
        if (clipboardReadFailure) throw new Error('clipboard read denied');
        return clipboard;
      },
    },
  },
  configurable: true,
  writable: true,
});
Object.defineProperty(globalThis, 'document', { value: documentStub, configurable: true, writable: true });
Object.defineProperty(globalThis, 'window', { value: windowStub, configurable: true, writable: true });

const originalLoad = Module._load;
Module._load = function patchedLoad(request, parent, isMain) {
  if (request === 'obsidian') return obsidianStub;
  return originalLoad.call(this, request, parent, isMain);
};
let XUSecretVault;
try {
  XUSecretVault = require(MAIN);
} finally {
  Module._load = originalLoad;
}

/* ---------------- 流程 ---------------- */

(async () => {
  const plugin = new XUSecretVault(app, {
    id: 'xu-secret-vault',
    name: 'XU Secret Vault',
    version: '0.1.1',
    minAppVersion: '1.13.0',
  });
  activePlugin = plugin;
  plugin.settings.vaultPath = VAULT_PATH;
  await plugin.onload();

  const restart = () => {
    // 模拟重启：K-09 的失败计数与退避只在内存，重启即清零
    plugin.failureCount = 0;
    plugin.blockedUntil = 0;
  };
  const unlockFresh = async (password) => {
    restart();
    return plugin.unlock(password);
  };
  const showSecret = () => {
    if (String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0) {
      const button = findButton(view.contentEl, '显示');
      if (button) button.click();
    }
  };
  const restoreVault = (text) => fileStore.set(VAULT_PATH, text);
  const goodText = () => fileStore.get(VAULT_PATH);

  ok(plugin.cryptoApi !== null, 'WebCrypto 探测可用');

  // 1) 首次使用 UI：创建保险库
  const leaf = await plugin.openVaultView();
  const view = leaf.view;
  await view.onOpen();
  await waitFor(() => plugin.vaultState !== 'unknown', '检测保险库状态');
  ok(String(textOf(view.contentEl)).indexOf('创建主密码') >= 0, '首次使用显示创建主密码界面');

  const passwordInputs = findAll(
    view.contentEl,
    (el) => el.tagName === 'INPUT' && el.type === 'password'
  );
  ok(passwordInputs.length === 2, '首次界面包含主密码与确认输入框');
  passwordInputs[0].value = MASTER;
  passwordInputs[1].value = MASTER;
  const createButton = findButton(view.contentEl, '创建保险库');
  ok(!!createButton, '找到创建保险库按钮');
  const createStart = Date.now();
  createButton.click();
  await waitFor(() => plugin.isUnlocked(), '创建保险库完成');
  const createMs = Date.now() - createStart;

  ok(fileStore.has(VAULT_PATH), '创建后生成密文文件 ' + VAULT_PATH);
  ok(!fileStore.has(VAULT_PATH + '.tmp'), '原子写完成后没有残留 .tmp');
  ok(plugin.isUnlocked(), '创建后自动解锁');
  ok(plugin.sessionKey.extractable === false, '会话密钥 non-extractable');
  ok(plugin.sessionSalt.length === 16, '盐为 16 字节');
  ok(plugin.entries.length === 0, '新保险库条目为空');
  ok(plugin.settings.initializedPath === VAULT_PATH, '记录已初始化路径（用于区分首次使用与文件缺失）');

  const env0 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env0.formatVersion === 1, '信封 formatVersion=1');
  ok(env0.kdf.algo === 'PBKDF2-SHA512', 'KDF 算法记录为 PBKDF2-SHA512');
  ok(Number(env0.kdf.iterations) === 600000, 'KDF 迭代数记录为 600000');
  ok(Buffer.from(env0.kdf.salt, 'base64').length === 16, '信封盐为 16 字节');
  ok(Buffer.from(env0.cipher.iv, 'base64').length === 12, '信封 IV 为 12 字节');
  ok(env0.cipher.algo === 'AES-256-GCM', '加密算法记录为 AES-256-GCM');
  ok(!('entries' in env0), '信封中不存在明文 entries 字段');
  ok(!('updatedAt' in env0), '信封头不再明文暴露 updatedAt');

  // 2) 通过 UI 新增条目
  const addButton = findButton(view.contentEl, '新增');
  ok(!!addButton, '找到新增按钮');
  addButton.click();
  const addModal = Array.from(plugin.openModals)[0];
  ok(!!addModal, '新增弹窗已打开');
  const modalInputs = findAll(addModal.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'text');
  const modalTextareas = findAll(addModal.contentEl, (el) => el.tagName === 'TEXTAREA');
  ok(modalInputs.length === 2 && modalTextareas.length === 2, '弹窗字段齐全（名称/标签/内容/备注）');
  ok(modalTextareas[0].getAttribute('spellcheck') === 'false', '内容输入框关闭拼写检查');
  ok(modalTextareas[0].getAttribute('autocomplete') === 'off', '内容输入框关闭自动填充');
  modalInputs[0].value = 'Alpha';
  modalInputs[1].value = 'work, cloud';
  modalTextareas[0].value = SECRET_ONE;
  modalTextareas[1].value = 'primary credential';
  const saveButton = findButton(addModal.contentEl, '保存');
  saveButton.click();
  await waitFor(() => !addModal.isOpen && plugin.entries.length === 1, '新增条目落盘');

  ok(plugin.entries[0].name === 'Alpha', '条目名称已保存');
  ok(plugin.entries[0].content === SECRET_ONE, '条目内容已保存在内存');
  ok(plugin.entries[0].tags.join(',') === 'work,cloud', '标签去重并保存');
  const env1 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env1.cipher.iv !== env0.cipher.iv, '新增写盘生成了新的 IV');
  ok(env1.kdf.salt === env0.kdf.salt, '同一保险库盐保持不变');

  // 3) 列表中默认不显示明文，点击「显示」后才出现
  ok(String(textOf(view.contentEl)).indexOf(SECRET_ONE) < 0, '列表中默认隐藏明文');
  const revealButton = findButton(view.contentEl, '显示');
  ok(!!revealButton, '找到显示按钮');
  revealButton.click();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_ONE) >= 0, '点击显示后明文出现在界面');

  // 4) 复制到剪贴板
  const copyButton = findButton(view.contentEl, '复制');
  copyButton.click();
  await waitFor(() => clipboard === SECRET_ONE, '复制到剪贴板');
  ok(clipboard === SECRET_ONE, '复制动作写入剪贴板');

  // 5) 编辑：内容默认掩码，点「显示」后才呈现（G-10）
  const editButton = findButton(view.contentEl, '编辑');
  editButton.click();
  const editModal = Array.from(plugin.openModals)[0];
  ok(!!editModal, '编辑弹窗已打开');
  ok(String(textOf(editModal.contentEl)).indexOf(SECRET_ONE) < 0, '编辑弹窗默认不回显明文');
  const modalReveal = findButton(editModal.contentEl, '显示');
  ok(!!modalReveal, '编辑弹窗提供显式显示按钮');
  modalReveal.click();
  const editTextareas = findAll(editModal.contentEl, (el) => el.tagName === 'TEXTAREA');
  ok(editTextareas.length === 2, '显形后出现内容与备注输入框');
  ok(editTextareas[0].value === SECRET_ONE, '显形后载入原明文');
  editTextareas[0].value = SECRET_TWO;
  findButton(editModal.contentEl, '保存').click();
  await waitFor(() => !editModal.isOpen, '编辑保存完成');
  ok(plugin.entries[0].content === SECRET_TWO, '编辑后的内容已更新');
  const env2 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env2.cipher.iv !== env1.cipher.iv, '编辑写盘生成了新的 IV');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_TWO) < 0, '负向：密文 blob 不含条目明文（编辑后）');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_ONE) < 0, '负向：密文 blob 不含旧明文');

  // 6) 锁定：同步清屏、关闭 Modal、清剪贴板、丢弃密钥、DOM 无明文
  showSecret();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '锁定前明文可见（构造测试场景）');

  findButton(view.contentEl, '编辑').click();
  const openModal = Array.from(plugin.openModals)[0];
  findButton(openModal.contentEl, '显示').click();
  ok(String(textOf(openModal.contentEl)).indexOf(SECRET_TWO) >= 0, '锁定前编辑弹窗显形后含明文');

  plugin.lock();
  ok(plugin.sessionKey === null, '锁定后 CryptoKey 已丢弃');
  ok(plugin.entries.length === 0, '锁定后内存条目集合已清空');
  ok(plugin.openModals.size === 0 && openModal.isOpen === false, '锁定关闭所有编辑弹窗');
  ok(String(textOf(openModal.contentEl)).indexOf(SECRET_TWO) < 0, '锁定后弹窗 DOM 不含明文');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：锁定后面板 DOM 不含明文');
  await waitFor(() => clipboard === '', '锁定后清空剪贴板');
  ok(clipboard === '', '锁定后剪贴板已清空');

  // 7) 关闭视图即清屏并锁定（M-09 / G-01）
  await unlockFresh(MASTER);
  view.render();
  showSecret();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '关闭视图前明文可见');
  await view.onClose();
  ok(plugin.sessionKey === null, '关闭视图触发锁定');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '关闭视图后 DOM 不含明文');
  view.render();

  // 8) 切后台遮罩 + 回到前台重新验证（M-05 / G-08）
  await unlockFresh(MASTER);
  view.render();
  showSecret();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '遮罩前明文可见');
  documentStub.hidden = true;
  documentStub.fire('visibilitychange');
  ok(view.masked === true, '切后台后立即加遮罩');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：遮罩后 DOM 不含明文');
  ok(String(textOf(view.contentEl)).indexOf('内容已隐藏') >= 0, '遮罩界面提示内容已隐藏');
  ok(plugin.sessionKey !== null, '遮罩但未超过 60 秒时保留会话密钥');
  documentStub.hidden = false;
  documentStub.fire('visibilitychange');
  ok(view.masked === true, '回到前台后仍保持遮罩，等待重新验证');
  const maskPassword = findAll(view.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'password')[0];
  ok(!!maskPassword, '遮罩界面提供主密码输入框');
  maskPassword.value = MASTER;
  findButton(view.contentEl, '验证并继续').click();
  await waitFor(() => view.masked === false, '重新验证主密码');
  ok(view.masked === false, '正确主密码解除遮罩');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '解除遮罩后不自动回显明文');

  // blur 同样遮罩
  showSecret();
  windowStub.fire('blur');
  ok(view.masked === true && String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '窗口失焦同样遮罩并清屏');

  // hidden 超过 60 秒直接锁定
  documentStub.hidden = true;
  documentStub.fire('visibilitychange');
  plugin.hiddenAt = Date.now() - 61000;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '后台超过 60 秒自动锁定');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：后台锁定后 DOM 不含明文');
  ok(notices.some((message) => message.indexOf('后台超过 60 秒') >= 0), '后台锁定给出提示');
  documentStub.hidden = false;
  documentStub.fire('visibilitychange');
  view.render();

  // 9) 加密层负向：AAD 保护（篡改迭代数 / 盐 / cipher 算法 / 版本 / base64）
  const goodEnvelopeText = goodText();
  const unified = plugin.t('err_unlock_failed');

  const tamperedIterations = JSON.parse(goodEnvelopeText);
  tamperedIterations.kdf.iterations = 1;
  restoreVault(JSON.stringify(tamperedIterations, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：篡改迭代数被拒绝');
  ok(plugin.lastUnlockError === unified, '篡改迭代数返回统一失败文案');
  restoreVault(goodEnvelopeText);

  const tamperedCipherAlgo = JSON.parse(goodEnvelopeText);
  tamperedCipherAlgo.cipher.algo = 'AES-128-GCM';
  restoreVault(JSON.stringify(tamperedCipherAlgo, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：篡改 cipher.algo 被拒绝（AAD 认证）');
  restoreVault(goodEnvelopeText);

  const tamperedSalt = JSON.parse(goodEnvelopeText);
  tamperedSalt.kdf.salt = Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString('base64');
  restoreVault(JSON.stringify(tamperedSalt, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：替换盐后无法解密');
  restoreVault(goodEnvelopeText);

  const tamperedVersion = JSON.parse(goodEnvelopeText);
  tamperedVersion.formatVersion = 2;
  restoreVault(JSON.stringify(tamperedVersion, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：版本不符被拒绝');
  restoreVault(goodEnvelopeText);

  restoreVault(String(goodEnvelopeText).slice(0, 120));
  ok((await unlockFresh(MASTER)) === false, '负向：截断的 JSON 统一失败且不抛原始异常');
  ok(plugin.lastUnlockError === unified, '截断 JSON 返回统一失败文案');
  restoreVault(goodEnvelopeText);

  const badIv = JSON.parse(goodEnvelopeText);
  badIv.cipher.iv = '***not-base64***';
  restoreVault(JSON.stringify(badIv, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：非法 base64 统一失败');
  restoreVault(goodEnvelopeText);

  const badPayload = JSON.parse(goodEnvelopeText);
  badPayload.payload = badPayload.payload.slice(0, 12) + 'AAAA' + badPayload.payload.slice(16);
  restoreVault(JSON.stringify(badPayload, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：密文被篡改导致 GCM 校验失败');
  restoreVault(goodEnvelopeText);

  // 10) 抗爆破：连续 5 次错误密码产生指数退避（K-09）
  restart();
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const waitMs = Math.max(0, plugin.blockedUntil - Date.now());
    if (waitMs) await delay(waitMs + 40);
    const failed = await plugin.unlock('wrong-master-' + attempt);
    ok(failed === false, '第 ' + attempt + ' 次错误密码被拒绝');
  }
  ok(plugin.failureCount === 5, '连续失败累计 5 次');
  ok(plugin.blockedUntil - Date.now() > 3000, '第 5 次失败后出现明显退避延迟');
  ok(plugin.getUnlockWaitSeconds() > 0, '退避期间返回剩余等待秒数');
  const blockedBefore = plugin.blockedUntil;
  restart();
  ok(blockedBefore > 0, '退避计时只在内存，可被重启清零');
  const unlockStart = Date.now();
  ok((await unlockFresh(MASTER)) === true, '正确主密码重新解锁成功');
  const unlockMs = Date.now() - unlockStart;
  ok(plugin.entries.length === 1 && plugin.entries[0].content === SECRET_TWO, '重新解锁后内容仍正确');
  ok(plugin.sessionKey.extractable === false, '重新解锁的密钥仍 non-extractable');

  // 11) 自动锁定同样清屏
  view.render();
  showSecret();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '自动锁定前明文可见');
  plugin.idleDeadline = Date.now() - 1;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '自动锁定丢弃 CryptoKey');
  ok(plugin.entries.length === 0, '自动锁定清空内存条目');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：自动锁定后面板 DOM 不含明文');
  ok(notices.some((message) => message.indexOf('自动锁定') >= 0), '自动锁定给出用户提示');

  // 12) 删除（UI 二次确认），再次解锁确认已删除
  await unlockFresh(MASTER);
  view.render();
  findButton(view.contentEl, '删除').click();
  const deleteModal = Array.from(plugin.openModals)[0];
  ok(!!deleteModal, '删除确认弹窗已打开');
  findButton(deleteModal.contentEl, '确认删除').click();
  await waitFor(() => plugin.entries.length === 0, '删除条目完成');
  ok(plugin.entries.length === 0, '条目已删除');
  const env3Text = fileStore.get(VAULT_PATH);
  ok(String(env3Text).indexOf(SECRET_TWO) < 0, '负向：删除后密文 blob 不含明文');

  plugin.lock();
  const unlockEmpty = await unlockFresh(MASTER);
  ok(unlockEmpty === true && plugin.entries.length === 0, '重新解锁后确认条目已删除');

  // 13) 并发保存：两次快速新增不得互相覆盖（D-04）
  const concurrentA = plugin.addEntry({ name: 'Concurrent-A', type: 'note', content: SECRET_ONE });
  const concurrentB = plugin.addEntry({ name: 'Concurrent-B', type: 'note', content: SECRET_THREE });
  await Promise.all([concurrentA, concurrentB]);
  ok(plugin.entries.length === 2, '并发两次新增都保留');
  ok(
    plugin.entries.some((entry) => entry.name === 'Concurrent-A') &&
      plugin.entries.some((entry) => entry.name === 'Concurrent-B'),
    '并发保存未丢失任何一次变更'
  );
  ok(!fileStore.has(VAULT_PATH + '.tmp'), '并发保存后无残留 .tmp');

  // 14) 原子写：模拟写到一半失败，旧 blob 必须完好且可解锁（D-02 / D-03）
  const beforeFailure = goodText();
  const entriesBefore = plugin.entries.length;
  writeBehavior = 'throw-partial';
  await rejects(
    plugin.addEntry({ name: 'Gamma', type: 'note', content: SECRET_THREE }),
    'simulated partial write',
    '负向：写盘中途报错时保存被拒绝'
  );
  writeBehavior = null;
  ok(plugin.entries.length === entriesBefore, '写盘失败后内存数据未更新');
  ok(goodText() === beforeFailure, '写盘失败后旧 blob 未被改动');
  ok(!fileStore.has(VAULT_PATH + '.tmp'), '写盘失败后清理了 .tmp');
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '写盘失败后旧 blob 仍可解锁');
  ok(plugin.entries.length === entriesBefore, '旧 blob 解锁后条目数量正确');

  // 15) 同步冲突：外部改动后拒绝覆盖，另存 conflict 副本（D-06 / S-02 / S-09）
  const externalText = goodText() + '\n';
  restoreVault(externalText);
  await plugin.addEntry({ name: 'Conflict', type: 'note', content: SECRET_THREE });
  const conflicts = Array.from(fileStore.keys()).filter((key) => key.indexOf('.conflict-') >= 0);
  ok(conflicts.length === 1, '检测到外部改动后生成 conflict 副本');
  ok(goodText() === externalText, '拒绝覆盖外部改动后的原文件');
  ok(plugin.entries.length === entriesBefore, '冲突时本次改动未静默合并进内存');
  ok(notices.some((message) => message.indexOf('外部修改') >= 0), '冲突时给出用户提示');
  ok(String(fileStore.get(conflicts[0])).indexOf(SECRET_THREE) < 0, '负向：conflict 副本仍是密文');
  restoreVault(goodText().replace(/\n$/, ''));

  // 16) 剪贴板读取失败时无条件清空（G-02）
  clipboard = '';
  await plugin.copySecret(SECRET_ONE);
  clipboardReadFailure = true;
  await plugin.clearClipboardIfOwned(false);
  clipboardReadFailure = false;
  ok(clipboard === '', '读剪贴板失败时仍无条件清空');
  ok(notices.some((message) => message.indexOf('无条件清空') >= 0), '强清给出提示');

  // 17) 保险库文件缺失：错误态而不是引导重新创建（D-10 / S-05）
  plugin.lock();
  fileStore.delete(VAULT_PATH);
  plugin.vaultState = 'unknown';
  view.render();
  await waitFor(() => plugin.vaultState !== 'unknown', '重新检测缺失状态');
  ok(String(textOf(view.contentEl)).indexOf('找不到保险库文件') >= 0, '文件缺失显示错误态');
  ok(String(textOf(view.contentEl)).indexOf('创建保险库') < 0, '文件缺失时不出现创建入口');
  ok((await unlockFresh(MASTER)) === false, '缺失时解锁返回 false');
  ok(plugin.lastUnlockError === plugin.t('err_vault_missing'), '缺失时返回专门文案');
  restoreVault(goodEnvelopeText);

  // 18) 明文不进入任何信封历史
  for (const [label, text] of [
    ['创建', JSON.stringify(env0)],
    ['新增', JSON.stringify(env1)],
    ['编辑', JSON.stringify(env2)],
    ['删除', env3Text],
    ['最终', goodText()],
  ]) {
    ok(
      text.indexOf(SECRET_ONE) < 0 &&
        text.indexOf(SECRET_TWO) < 0 &&
        text.indexOf(SECRET_THREE) < 0 &&
        text.indexOf(MASTER) < 0,
      '负向：' + label + '后的密文不含任何明文或主密码'
    );
  }

  // 19) 主密码与明文不进入设置持久化
  await plugin.saveSettings();
  const settingsText = JSON.stringify(plugin.settings);
  ok(settingsText.indexOf(MASTER) < 0, '设置对象不含主密码');
  ok(settingsText.indexOf(SECRET_ONE) < 0 && settingsText.indexOf(SECRET_TWO) < 0, '设置对象不含条目明文');
  const savedText = JSON.stringify(plugin.__savedData);
  ok(savedText.indexOf(MASTER) < 0 && savedText.indexOf(SECRET_TWO) < 0, 'data.json 写入记录不含主密码或明文');

  // 20) crypto.subtle 不可用时明确报错
  plugin.lock();
  const savedCrypto = plugin.cryptoApi;
  plugin.cryptoApi = null;
  view.render();
  ok(String(textOf(view.contentEl)).indexOf('WebCrypto') >= 0, '无 WebCrypto 时界面明确提示');
  plugin.cryptoApi = savedCrypto;
  view.render();

  // 收尾断言：命令与视图存在
  ok(plugin.__commands.length === 3, '注册了 3 条命令');
  ok(plugin.__viewFactories['xu-secret-vault-view'] !== undefined, '注册了侧边栏视图');
  ok(plugin.__settingTab !== null, '注册了设置页');

  console.log('');
  console.log('CREATE_MS=' + createMs + '  UNLOCK_MS=' + unlockMs);
  console.log('ASSERTIONS=' + assertions + '  FAILURES=' + failures.length);
  if (failures.length) {
    console.error('FAILED:');
    for (const failure of failures) console.error(' - ' + failure);
    process.exit(1);
  }
  console.log('E2E_ALL_PASS');
  process.exit(0);
})().catch((error) => {
  console.error('E2E_FATAL', error);
  process.exit(1);
});
