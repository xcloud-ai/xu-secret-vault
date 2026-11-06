/* XU Secret Vault 0.1.5 — e2e / 安全加固负向测试（Node 原生 WebCrypto + Obsidian 桩） */
'use strict';

const fs = require('fs');
const path = require('path');
const Module = require('module');
const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

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

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(text) {
  return new Uint8Array(Buffer.from(String(text), 'base64'));
}

function tmpFiles() {
  return Array.from(fileStore.keys()).filter((key) => key.indexOf(VAULT_PATH + '.tmp') === 0);
}

function bakFiles() {
  return Array.from(fileStore.keys()).filter((key) => key.indexOf(VAULT_PATH + '.bak') === 0);
}

function conflictFiles() {
  return Array.from(fileStore.keys()).filter((key) => key.indexOf('.conflict-') >= 0);
}

// 手工构造 v1（0.1.0）信封：AAD = xsv-aad-v1|1|PBKDF2-SHA512|600000|salt（不含 cipher.algo）
async function buildLegacyV1Envelope(password, entries) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password.normalize('NFC')),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-512' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(
    ['xsv-aad-v1', 1, 'PBKDF2-SHA512', '600000', toBase64(salt)].join('|')
  );
  const plaintext = JSON.stringify({ version: 1, entries });
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    formatVersion: 1,
    kdf: { algo: 'PBKDF2-SHA512', iterations: 600000, salt: toBase64(salt) },
    cipher: { algo: 'AES-256-GCM', iv: toBase64(iv) },
    payload: toBase64(ciphertext),
  };
}

// 手工构造 v2 信封，但载荷只有 entries（没有 notes / contentVersion），用于验证旧结构兼容
async function buildV2EnvelopeWithoutNotes(password, entries) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const material = await subtle.importKey(
    'raw',
    new TextEncoder().encode(password.normalize('NFC')),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-512' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(
    ['xsv-aad-v2', 2, 'PBKDF2-SHA512', '600000', toBase64(salt), 'AES-256-GCM'].join('|')
  );
  const plaintext = JSON.stringify({ version: 2, entries });
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    formatVersion: 2,
    kdf: { algo: 'PBKDF2-SHA512', iterations: 600000, salt: toBase64(salt) },
    cipher: { algo: 'AES-256-GCM', iv: toBase64(iv) },
    payload: toBase64(ciphertext),
  };
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
    style: {},
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
  el.appendText = (text) => {
    el.textContent += String(text);
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
let renameCorruptOnce = false; // 模拟 rename 后终检失败（用于测试 .bak 回滚）
let removeFailure = false; // 模拟删除原文件失败（回滚分支）
let renameTargetFailureOnce = false; // 模拟 tmp 落位 rename 失败
let afterReadHook = null; // 读取后注入外部改动（模拟 TOCTOU 窗口）
let activePlugin = null;

const app = {
  vault: {
    adapter: {
      exists: async (filePath) => fileStore.has(filePath) || createdDirs.has(filePath),
      read: async (filePath) => {
        if (!fileStore.has(filePath)) throw new Error('file not found: ' + filePath);
        const text = fileStore.get(filePath);
        if (afterReadHook) {
          const hook = afterReadHook;
          afterReadHook = null;
          hook(filePath, text);
        }
        return text;
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
        // 真实 Obsidian DataAdapter.rename：目标已存在时直接抛错，不会静默覆盖
        if (fileStore.has(toPath)) throw new Error('Destination file already exists!');
        if (renameCorruptOnce && toPath === VAULT_PATH) {
          renameCorruptOnce = false;
          // rename 成功但落盘内容损坏：触发 rename 后的终检失败与 .bak 回滚
          fileStore.set(toPath, 'CORRUPTED');
          fileStore.delete(fromPath);
          return;
        }
        if (renameTargetFailureOnce && toPath === VAULT_PATH) {
          renameTargetFailureOnce = false;
          throw new Error('simulated rename failure');
        }
        fileStore.set(toPath, fileStore.get(fromPath));
        fileStore.delete(fromPath);
      },
      remove: async (filePath) => {
        if (removeFailure && filePath === VAULT_PATH) throw new Error('simulated remove failure');
        fileStore.delete(filePath);
      },
      stat: async (filePath) =>
        fileStore.has(filePath) ? { size: Buffer.byteLength(fileStore.get(filePath), 'utf8') } : null,
      mkdir: async (dirPath) => {
        createdDirs.add(dirPath);
      },
      list: async (dirPath) => ({
        files: Array.from(fileStore.keys()).filter((key) => {
          const slash = key.lastIndexOf('/');
          return slash < 0 ? dirPath === '' : key.slice(0, slash) === dirPath;
        }),
        folders: [],
      }),
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
    version: '0.2.1',
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
  ok(tmpFiles().length === 0, '原子写完成后没有残留 .tmp');
  ok(plugin.isUnlocked(), '创建后自动解锁');
  ok(plugin.sessionKey.extractable === false, '会话密钥 non-extractable');
  ok(plugin.sessionSalt.length === 16, '盐为 16 字节');
  ok(plugin.entries.length === 0, '新保险库条目为空');
  ok(plugin.settings.initializedPath === VAULT_PATH, '记录已初始化路径（用于区分首次使用与文件缺失）');

  const env0 = JSON.parse(fileStore.get(VAULT_PATH));
  ok(env0.formatVersion === 2, '信封 formatVersion=2');
  ok(env0.kdf.algo === 'PBKDF2-SHA512', 'KDF 算法记录为 PBKDF2-SHA512');
  ok(Number(env0.kdf.iterations) === 600000, 'KDF 迭代数记录为 600000');
  ok(Buffer.from(env0.kdf.salt, 'base64').length === 16, '信封盐为 16 字节');
  ok(Buffer.from(env0.cipher.iv, 'base64').length === 12, '信封 IV 为 12 字节');
  ok(env0.cipher.algo === 'AES-256-GCM', '加密算法记录为 AES-256-GCM');
  ok(!('entries' in env0), '信封中不存在明文 entries 字段');
  ok(!('updatedAt' in env0), '信封头不再明文暴露 updatedAt');

  // 1b) 启动清理：只删本插件生成且超过 1 小时的 tmp，不得误删用户文件
  const nowStamp = (() => {
    const now = new Date();
    const pad = (value) => String(value).padStart(2, '0');
    return (
      String(now.getFullYear()) +
      pad(now.getMonth() + 1) +
      pad(now.getDate()) +
      '-' +
      pad(now.getHours()) +
      pad(now.getMinutes()) +
      pad(now.getSeconds())
    );
  })();
  fileStore.set(VAULT_PATH + '.tmp-20200101-000000-deadbeef', 'stale');
  fileStore.set(VAULT_PATH + '.tmp-notes.md', 'user file, not ours');
  fileStore.set(VAULT_PATH + '.tmp-20200101-000000-toolong123', 'invalid random length');
  fileStore.set(VAULT_PATH + '.tmp-' + nowStamp + '-abcdef12', 'possibly in-flight');
  await plugin.cleanupStaleTempFiles();
  ok(!fileStore.has(VAULT_PATH + '.tmp-20200101-000000-deadbeef'), '启动清理删除超 1 小时的合法 tmp');
  ok(fileStore.get(VAULT_PATH + '.tmp-notes.md') === 'user file, not ours', '用户文件 tmp-notes.md 不被误删');
  ok(fileStore.has(VAULT_PATH + '.tmp-20200101-000000-toolong123'), '随机段超长的非本插件命名不被删除');
  ok(fileStore.has(VAULT_PATH + '.tmp-' + nowStamp + '-abcdef12'), '1 小时内的 tmp（可能正在写）不被删除');
  fileStore.delete(VAULT_PATH + '.tmp-notes.md');
  fileStore.delete(VAULT_PATH + '.tmp-20200101-000000-toolong123');
  fileStore.delete(VAULT_PATH + '.tmp-' + nowStamp + '-abcdef12');

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
  ok(!fileStore.has(VAULT_PATH + '.bak'), '目标已存在时首次保存成功替换且不残留 .bak');
  ok(tmpFiles().length === 0, '首次保存不残留 .tmp');

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
  ok(!fileStore.has(VAULT_PATH + '.bak') && tmpFiles().length === 0, '连续保存不残留 .bak / .tmp');
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
  plugin.hiddenAt = plugin.nowMs() - 61000;
  plugin.hiddenAtWall = Date.now() - 61000;
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
  tamperedVersion.formatVersion = 3;
  restoreVault(JSON.stringify(tamperedVersion, null, 2));
  ok((await unlockFresh(MASTER)) === false, '负向：未知版本被拒绝');
  ok(plugin.lastUnlockError === plugin.t('err_version_unsupported'), '未知版本明确提示「版本不支持」');
  ok(plugin.lastUnlockError !== unified, '未知版本不与密码错误混同');
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

  // 9b) 文件超限：独立文案、不累计失败次数、不触发退避（状态错误不是密码错误）
  restoreVault('x'.repeat(9 * 1024 * 1024));
  plugin.lock();
  restart();
  ok((await plugin.unlock(MASTER)) === false, '负向：超过 8 MB 的保险库被拒绝读取');
  ok(plugin.lastUnlockError === plugin.t('err_vault_too_large'), '超限文案与密码错误明确区分');
  ok(plugin.lastUnlockError !== plugin.t('err_unlock_failed'), '超限不与密码错误混同');
  ok(plugin.failureCount === 0 && plugin.getUnlockWaitSeconds() === 0, '超限不计入爆破退避，不罚用户等待');
  restoreVault(goodEnvelopeText);

  // 10) 抗爆破：连续 5 次错误密码产生指数退避（K-09）
  restart();
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const waitMs = Math.max(0, plugin.blockedUntil - plugin.nowMs());
    if (waitMs) await delay(waitMs + 40);
    const failed = await plugin.unlock('wrong-master-' + attempt);
    ok(failed === false, '第 ' + attempt + ' 次错误密码被拒绝');
  }
  ok(plugin.failureCount === 5, '连续失败累计 5 次');
  ok(plugin.blockedUntil - plugin.nowMs() > 3000, '第 5 次失败后出现明显退避延迟');
  ok(plugin.getUnlockWaitSeconds() > 0, '退避期间返回剩余等待秒数');
  const blockedBefore = plugin.blockedUntil;
  restart();
  ok(blockedBefore > 0, '退避计时只在内存，可被重启清零');
  const unlockStart = Date.now();
  ok((await unlockFresh(MASTER)) === true, '正确主密码重新解锁成功');
  const unlockMs = Date.now() - unlockStart;
  ok(plugin.entries.length === 1 && plugin.entries[0].content === SECRET_TWO, '重新解锁后内容仍正确');
  ok(plugin.sessionKey.extractable === false, '重新解锁的密钥仍 non-extractable');

  // 10b) 弹窗揭示明文后失焦：关闭弹窗、清屏、未重验不可读（G-08 / suspended）
  view.render();
  const modalEditButton = findButton(view.contentEl, '编辑');
  ok(!!modalEditButton, '解锁列表提供编辑入口');
  modalEditButton.click();
  const entryModal = Array.from(plugin.openModals)[0];
  ok(!!entryModal, '编辑弹窗已打开');
  findButton(entryModal.contentEl, '显示').click();
  ok(String(textOf(entryModal.contentEl)).indexOf(SECRET_TWO) >= 0, '弹窗中已揭示明文');
  windowStub.fire('blur');
  await delay(20);
  ok(entryModal.isOpen === false && plugin.openModals.size === 0, '失焦后关闭本插件所有弹窗');
  ok(String(textOf(entryModal.contentEl)).indexOf(SECRET_TWO) < 0, '负向：弹窗关闭后 DOM 不含明文');
  ok(plugin.suspended === true, '失焦后进入挂起态');
  ok(view.masked === true, '失焦后面板加遮罩');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：遮罩后 DOM 不含明文');
  ok(plugin.sessionKey !== null, '挂起但未超时仍保留会话密钥');

  // 遮罩期间命令入口与写操作一律拒绝
  const addCommand = plugin.__commands.find((command) => command.id === 'new-entry');
  ok(!!addCommand, '新增条目命令已注册');
  addCommand.callback();
  await delay(80);
  ok(plugin.openModals.size === 0, '负向：遮罩期间执行「新增条目」命令被拒绝');
  ok(notices.some((message) => message.indexOf('挂起') >= 0), '拒绝时提示需重新验证');
  await rejects(
    plugin.addEntry({ name: 'MaskedAdd', type: 'note', content: SECRET_ONE }),
    '挂起',
    '负向：遮罩期间写操作被拒绝'
  );
  clipboard = '';
  await plugin.copySecret(SECRET_TWO);
  ok(clipboard === '', '负向：遮罩期间复制被拒绝');
  ok(plugin.entries.length === 1, '遮罩期间未写入任何新条目');

  // 回前台（未超时）仍保持遮罩，必须重验
  documentStub.hidden = false;
  documentStub.fire('visibilitychange');
  ok(view.masked === true, '回前台未重验时仍不可读');
  const maskInput = findAll(view.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'password')[0];
  ok(!!maskInput, '遮罩界面提供重验输入框');
  maskInput.value = MASTER;
  findButton(view.contentEl, '验证并继续').click();
  await waitFor(() => view.masked === false, '重验后恢复');
  ok(view.masked === false && plugin.suspended === false, '重验成功后恢复可读');

  // 10c) 重验连续错误：复用失败计数与指数退避，退避期间不做 KDF
  windowStub.fire('blur');
  ok(plugin.suspended === true, '再次失焦进入挂起态');
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const waitMs = Math.max(0, plugin.blockedUntil - plugin.nowMs());
    if (waitMs) await delay(waitMs + 40);
    ok((await plugin.reverify('wrong-' + attempt)) === false, '第 ' + attempt + ' 次重验错误被拒绝');
  }
  const reverifyBlocked = plugin.blockedUntil - plugin.nowMs();
  ok(reverifyBlocked > 1000, '重验连续失败后出现指数退避');
  const quickStart = Date.now();
  ok((await plugin.reverify(MASTER)) === false, '退避期间正确密码也被拒绝');
  ok(Date.now() - quickStart < 50, '退避期间立即返回，不付出 KDF 成本');
  ok(plugin.lastReverifyError.indexOf('秒') >= 0, '退避提示包含剩余秒数');
  await delay(reverifyBlocked + 60);
  ok((await plugin.reverify(MASTER)) === true, '退避结束后正确密码可解除挂起');
  ok(plugin.suspended === false && view.masked === false, '重验成功解除遮罩');

  // 11) 自动锁定同样清屏
  view.render();
  showSecret();
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) >= 0, '自动锁定前明文可见');
  plugin.idleDeadline = plugin.nowMs() - 1;
  plugin.idleDeadlineWall = Date.now() - 1;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '自动锁定丢弃 CryptoKey');
  ok(plugin.entries.length === 0, '自动锁定清空内存条目');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '负向：自动锁定后面板 DOM 不含明文');
  ok(notices.some((message) => message.indexOf('自动锁定') >= 0), '自动锁定给出用户提示');

  // 11b) 多面板共享会话：已有解锁态面板时，新开面板必须以挂起态打开并需重验（M-11）
  await unlockFresh(MASTER);
  view.render();
  await view.onOpen();
  const leaf2 = { app, view: null };
  const view2 = plugin.__viewFactories['xu-secret-vault-view'](leaf2);
  leaf2.view = view2;
  leaves.push(leaf2);
  await view2.onOpen();
  ok(view2.masked === true, '新开面板以挂起态打开，不直接显示内容');
  ok(plugin.suspended === true, '新开面板触发挂起态');
  ok(view.masked === true, '原面板同步进入遮罩');
  ok(String(textOf(view2.contentEl)).indexOf(SECRET_TWO) < 0, '负向：新面板 DOM 不含明文');
  ok(String(textOf(view2.contentEl)).indexOf('验证并继续') >= 0, '新面板要求重新验证主密码');
  const panelPassword = findAll(view2.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'password')[0];
  ok(!!panelPassword, '新面板提供重验输入框');
  panelPassword.value = MASTER;
  findButton(view2.contentEl, '验证并继续').click();
  await waitFor(() => view2.masked === false, '新面板重验通过');
  ok(view2.masked === false && view.masked === false, '重验后两个面板同时解除遮罩');
  ok(plugin.suspended === false, '重验后退出挂起态');
  leaves.splice(leaves.indexOf(leaf2), 1);
  await view2.onClose();
  ok(plugin.isUnlocked() === false, '关闭新开面板后插件保持锁定，不会误解锁');
  ok(String(textOf(view.contentEl)).indexOf(SECRET_TWO) < 0, '旧面板回到锁定界面且不含明文');

  // 11c) 合盖休眠：单调钟（performance.now）不前进、墙钟前进 20 分钟 → 必须锁定（M-04）
  await unlockFresh(MASTER);
  view.render();
  plugin.idleDeadline = plugin.nowMs() + 10 * 60000;
  plugin.idleDeadlineWall = Date.now() - 20 * 60000;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '合盖唤醒后靠墙钟死线触发自动锁定');
  ok(plugin.entries.length === 0, '合盖唤醒锁定后内存条目已清空');
  ok(notices.some((message) => message.indexOf('自动锁定') >= 0), '合盖唤醒锁定给出提示');

  // hiddenAt 的 60 秒判定同样取墙钟：单调钟只过了 1 秒，墙钟过了 61 秒
  await unlockFresh(MASTER);
  plugin.hiddenAt = plugin.nowMs() - 1000;
  plugin.hiddenAtWall = Date.now() - 61000;
  plugin.checkAutoLock();
  ok(plugin.sessionKey === null, '后台 60 秒判定在休眠场景同样靠墙钟兜底');
  plugin.hiddenAt = 0;
  plugin.hiddenAtWall = 0;

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
  ok(tmpFiles().length === 0, '并发保存后无残留 .tmp');

  // 14) 原子写：模拟写到一半失败，旧 blob 必须完好且可解锁（D-02 / D-03）
  const beforeFailure = goodText();
  const entriesBefore = plugin.entries.length;
  writeBehavior = 'throw-partial';
  await rejects(
    plugin.addEntry({ name: 'Gamma', type: 'note', content: SECRET_THREE }),
    '无法写入保险库文件',
    '负向：写盘中途报错时保存被拒绝，且抛出中文文案'
  );
  writeBehavior = null;
  ok(plugin.entries.length === entriesBefore, '写盘失败后内存数据未更新');
  ok(goodText() === beforeFailure, '写盘失败后旧 blob 未被改动');
  ok(tmpFiles().length === 0, '写盘失败后清理了 .tmp');
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '写盘失败后旧 blob 仍可解锁');
  ok(plugin.entries.length === entriesBefore, '旧 blob 解锁后条目数量正确');

  // 14b) rename 后终检失败：必须回滚 .bak，且 knownBlobHash 同步修正（D-02 / 回滚）
  const beforeTerminal = goodText();
  renameCorruptOnce = true;
  await rejects(
    plugin.addEntry({ name: 'Terminal', type: 'note', content: SECRET_ONE }),
    '写入校验失败',
    '负向：rename 后终检失败被识别'
  );
  renameCorruptOnce = false;
  ok(goodText() === beforeTerminal, '终检失败后回滚到 .bak，旧密文恢复');
  ok(bakFiles().length === 0, '回滚成功后清理 .bak');
  ok(tmpFiles().length === 0, '终检失败后无残留 .tmp');
  ok(plugin.entries.length === entriesBefore, '终检失败后内存条目未更新');
  ok(
    (await plugin.hashText(goodText())) === plugin.knownBlobHash,
    '回滚后 knownBlobHash 已同步，避免下一次误判冲突'
  );
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '终检回滚后旧库仍可解锁');
  ok(plugin.entries.length === entriesBefore, '终检回滚后条目内容仍正确');
  view.render();

  // 14c) 回滚失败：保留 .bak，错误文案给出可恢复路径
  const beforeRollback = goodText();
  renameCorruptOnce = true;
  removeFailure = true;
  let rollbackError = null;
  try {
    await plugin.addEntry({ name: 'RollbackFail', type: 'note', content: SECRET_TWO });
  } catch (error) {
    rollbackError = error;
  }
  removeFailure = false;
  renameCorruptOnce = false;
  const bakPath = VAULT_PATH + '.bak';
  ok(rollbackError !== null, '回滚失败时写操作报错');
  ok(String(rollbackError && rollbackError.message).indexOf(bakPath) >= 0, '错误文案包含 .bak 恢复路径');
  ok(fileStore.has(bakPath), '回滚失败时保留 .bak 文件');
  fileStore.set(VAULT_PATH, fileStore.get(bakPath));
  fileStore.delete(bakPath);
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '按恢复路径从旧密文恢复后仍可解锁');
  ok(plugin.entries.length === entriesBefore, '恢复后条目数量正确');

  // 14d) 原文件本不存在：没有 .bak，文案不得指向不存在的文件
  plugin.lock();
  fileStore.delete(VAULT_PATH);
  renameCorruptOnce = true;
  removeFailure = true;
  let createError = null;
  try {
    await plugin.createVault(MASTER);
  } catch (error) {
    createError = error;
  }
  removeFailure = false;
  renameCorruptOnce = false;
  ok(createError !== null, '无原文件时创建失败仍抛出异常');
  ok(
    String(createError && createError.message).indexOf('.bak') < 0 &&
      String(createError && createError.message).indexOf('已保留旧密文备份') < 0,
    '未生成 .bak 时文案不指向不存在的文件'
  );
  ok(!fileStore.has(VAULT_PATH + '.bak'), '未生成 .bak 时不出现备份文件');
  fileStore.set(VAULT_PATH, beforeRollback);
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, '恢复正式库后仍可解锁');
  ok(plugin.entries.length === entriesBefore, '恢复正式库后条目数量正确');

  // 14f) createVault 的 mustNotExist：目标已存在时给中文提示，不暴露 adapter 英文原串
  let existsError = null;
  try {
    await plugin.createVault(MASTER);
  } catch (error) {
    existsError = error;
  }
  ok(String(existsError && existsError.message) === plugin.t('err_vault_exists'), '创建时目标已存在给出中文提示');
  ok(goodText() === beforeRollback, '创建被拒后旧库文件未被改动');

  // 14e) tmp 落位 rename 失败：回滚把旧库从 .bak 改名回来，旧库仍可解锁且错误为中文
  const beforeRenameFail = goodText();
  renameTargetFailureOnce = true;
  let renameError = null;
  try {
    await plugin.addEntry({ name: 'RenameFail', type: 'note', content: SECRET_TWO });
  } catch (error) {
    renameError = error;
  }
  renameTargetFailureOnce = false;
  ok(renameError !== null, 'rename 落位失败时写操作报错');
  ok(String(renameError && renameError.message) === plugin.t('err_save_failed'), '错误文案是中文 err_save_failed，不是 adapter 英文原串');
  ok(goodText() === beforeRenameFail, 'rename 失败回滚后旧库字节不变');
  ok(!fileStore.has(VAULT_PATH + '.bak'), '回滚成功后清理 .bak');
  plugin.lock();
  ok((await unlockFresh(MASTER)) === true, 'rename 失败回滚后旧库仍可解锁');
  ok(plugin.entries.length === entriesBefore, 'rename 失败回滚后条目内容仍正确');

  // 15) 同步冲突：外部改动后拒绝覆盖，另存 conflict 副本（D-06 / S-02 / S-09）
  const hashBeforeConflict = plugin.knownBlobHash;
  const externalText = goodText() + '\n';
  restoreVault(externalText);
  await plugin.addEntry({ name: 'Conflict', type: 'note', content: SECRET_THREE });
  const conflicts = conflictFiles();
  ok(conflicts.length === 1, '检测到外部改动后生成 conflict 副本');
  ok(goodText() === externalText, '拒绝覆盖外部改动后的原文件');
  ok(plugin.entries.length === entriesBefore, '冲突时本次改动未静默合并进内存');
  ok(plugin.conflictPending === true, '冲突后进入只读冲突态');
  ok(notices.some((message) => message.indexOf('另存副本') >= 0), '冲突文案明确：已另存副本、原文件未覆盖');
  ok(String(fileStore.get(conflicts[0])).indexOf(SECRET_THREE) < 0, '负向：conflict 副本仍是密文');
  ok(plugin.knownBlobHash === hashBeforeConflict, '冲突副本写盘不污染 knownBlobHash（基线仍指向真实保险库）');
  await rejects(
    plugin.addEntry({ name: 'AfterConflict', type: 'note', content: SECRET_ONE }),
    '重新加载',
    '负向：冲突未重载前禁止继续编辑'
  );
  const reloaded = await plugin.reloadFromConflict();
  ok(reloaded === true && plugin.conflictPending === false, '重新加载后解除冲突态');
  ok(plugin.entries.length === entriesBefore, '重新加载后内存与磁盘一致');

  // 15b) TOCTOU：加密/校验期间外部写入（rename 前复核）不得被静默覆盖
  const raceBase = goodText();
  const raceExternal = raceBase + '\n';
  afterReadHook = (filePath) => {
    if (filePath === VAULT_PATH) fileStore.set(VAULT_PATH, raceExternal);
  };
  const raceResult = await plugin.addEntry({ name: 'Race', type: 'note', content: SECRET_TWO });
  afterReadHook = null;
  ok(goodText() === raceExternal, '加密窗口内的外部写入未被静默覆盖');
  ok(raceResult === false, 'TOCTOU 冲突时保存返回失败');
  ok(plugin.conflictPending === true, 'TOCTOU 冲突同样进入只读冲突态');
  ok(plugin.entries.length === entriesBefore, 'TOCTOU 冲突不更新内存快照');
  ok(conflictFiles().length === 2, 'TOCTOU 冲突也另存副本');
  ok((await plugin.reloadFromConflict()) === true && plugin.conflictPending === false, 'TOCTOU 冲突可重载恢复');


  // 16) 剪贴板只在确认内容仍是本插件写入值时才清（G-02）
  notices.length = 0;
  clipboard = '';
  await plugin.copySecret(SECRET_ONE);
  clipboardReadFailure = true;
  await plugin.clearClipboardIfOwned(true);
  clipboardReadFailure = false;
  ok(clipboard === SECRET_ONE, '负向：读剪贴板失败时不清空，避免误删用户内容');
  ok(notices.some((message) => message.indexOf('手动检查') >= 0), '读取失败时提示手动检查');

  await plugin.copySecret(SECRET_ONE);
  clipboard = 'USER-OWN-CLIPBOARD';
  await plugin.clearClipboardIfOwned(true);
  ok(clipboard === 'USER-OWN-CLIPBOARD', '负向：内容已被用户替换时不清空');

  clipboard = '';
  await plugin.copySecret(SECRET_ONE);
  await plugin.clearClipboardIfOwned(true);
  ok(clipboard === '', '确认仍为本插件写入值时清空');
  ok(notices.some((message) => message.indexOf('剪贴板中的密钥已清空') >= 0), '确认清空后给出提示');

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

  // 19b) v1 兼容读取与自动升级 / 未知版本明确提示（发社区前必须有）
  const legacy = await buildLegacyV1Envelope(MASTER, [
    {
      id: 'legacy-1',
      name: 'Legacy Entry',
      type: 'note',
      content: SECRET_ONE,
      tags: ['legacy'],
      note: '',
      createdAt: '',
      updatedAt: '',
    },
  ]);
  restoreVault(JSON.stringify(legacy, null, 2));
  plugin.lock();
  restart();
  ok((await plugin.unlock(MASTER)) === true, 'v1 旧信封可兼容解锁');
  ok(plugin.entries.length === 1 && plugin.entries[0].content === SECRET_ONE, 'v1 条目内容正确');
  const upgraded = JSON.parse(fileStore.get(VAULT_PATH));
  ok(upgraded.formatVersion === 2, 'v1 读取成功后自动升级为 v2');
  ok(notices.some((message) => message.indexOf('升级') >= 0), '升级给出提示');
  ok(String(fileStore.get(VAULT_PATH)).indexOf(SECRET_ONE) < 0, '负向：升级后的密文不含明文');

  const unknownVersion = JSON.parse(fileStore.get(VAULT_PATH));
  unknownVersion.formatVersion = 3;
  restoreVault(JSON.stringify(unknownVersion, null, 2));
  plugin.lock();
  restart();
  ok((await plugin.unlock(MASTER)) === false, '负向：未知版本解锁被拒绝');
  ok(plugin.lastUnlockError === plugin.t('err_version_unsupported'), '未知版本提示「版本不支持」');
  ok(plugin.lastUnlockError !== plugin.t('err_unlock_failed'), '未知版本不和密码错误混同');
  restoreVault(JSON.stringify(upgraded, null, 2));

  // 19c) v1 升级失败：本次仍可解锁，失败提示只出现一次
  restoreVault(JSON.stringify(legacy, null, 2));
  plugin.lock();
  restart();
  notices.length = 0;
  writeBehavior = 'throw-before';
  ok((await plugin.unlock(MASTER)) === true, 'v1 升级写盘失败不影响本次解锁');
  ok(notices.some((message) => message.indexOf('升级失败') >= 0), '升级失败给出一次提示');
  ok(JSON.parse(fileStore.get(VAULT_PATH)).formatVersion === 1, '升级失败后继续使用旧格式');
  plugin.lock();
  restart();
  notices.length = 0;
  ok((await plugin.unlock(MASTER)) === true, '再次解锁 v1 仍成功');
  ok(!notices.some((message) => message.indexOf('升级失败') >= 0), '升级失败提示不重复');
  writeBehavior = null;
  restoreVault(JSON.stringify(upgraded, null, 2));
  plugin.lock();

  // 19d) 冲突副本枚举与显式选择（S-07）：不自动挑选，选定后加载对应文件
  for (const stale of conflictFiles()) fileStore.delete(stale);
  const conflictCopy = VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200101-000000.enc';
  fileStore.set(conflictCopy, fileStore.get(VAULT_PATH));
  await plugin.lock();
  await plugin.scanVaultSources();
  ok(plugin.vaultSources.length === 2, '解锁前枚举到正式库与冲突副本');
  ok(plugin.vaultSources[0] === VAULT_PATH, '正式库排在首位');
  ok(plugin.selectedVaultPath === '' && plugin.getVaultPath() === VAULT_PATH, '默认不自动挑选冲突副本');
  view.render();
  ok(String(textOf(view.contentEl)).indexOf('选择要加载的保险库文件') >= 0, '解锁界面显示候选库列表');
  ok(String(textOf(view.contentEl)).indexOf('请确认要解锁的是哪一个文件') >= 0, '提示需由用户确认选择');
  const sourceButton = findButton(view.contentEl, conflictCopy);
  ok(!!sourceButton, '候选列表包含冲突副本');
  sourceButton.click();
  ok(plugin.selectedVaultPath === conflictCopy, '点击后显式选中冲突副本');
  view.render();
  const sourcePassword = findAll(view.contentEl, (el) => el.tagName === 'INPUT' && el.type === 'password')[0];
  sourcePassword.value = MASTER;
  findButton(view.contentEl, '解锁').click();
  await waitFor(() => plugin.isUnlocked(), '加载所选冲突副本');
  ok(plugin.entries.length === 1 && plugin.entries[0].content === SECRET_ONE, '从所选副本加载内容');

  // 19d-2) 副本只读：隐藏写入口、显示横幅、保留复制；写操作拒绝且两个文件字节都不变
  view.render();
  ok(plugin.isReadOnlyCopy() === true, '选中副本后进入只读态');
  ok(String(textOf(view.contentEl)).indexOf('正在查看冲突副本（只读）') >= 0, '显示只读横幅');
  ok(String(textOf(view.contentEl)).indexOf('不会写回正式保险库') >= 0, '横幅明确不会写回正式库');
  ok(!findButton(view.contentEl, '新增'), '只读态隐藏新增入口');
  ok(!findButton(view.contentEl, '编辑'), '只读态隐藏编辑入口');
  ok(!findButton(view.contentEl, '删除'), '只读态隐藏删除入口');
  ok(!!findButton(view.contentEl, '复制'), '只读态保留复制入口');
  const canonicalBeforeWrite = fileStore.get(VAULT_PATH);
  const copyBeforeWrite = fileStore.get(conflictCopy);
  await rejects(
    plugin.addEntry({ name: 'CopyWrite', type: 'note', content: SECRET_TWO }),
    '只读',
    '负向：只读副本上的新增被拒'
  );
  await rejects(
    plugin.updateEntry(plugin.entries[0].id, { name: 'CopyEdit', type: 'note', content: SECRET_TWO }),
    '只读',
    '负向：只读副本上的编辑被拒'
  );
  await rejects(
    plugin.deleteEntry(plugin.entries[0].id),
    '只读',
    '负向：只读副本上的删除被拒'
  );
  ok(fileStore.get(VAULT_PATH) === canonicalBeforeWrite, '正式库文件字节未变');
  ok(fileStore.get(conflictCopy) === copyBeforeWrite, '副本文件字节未变');

  plugin.lock();
  await plugin.scanVaultSources();
  ok(plugin.selectedVaultPath === '' && plugin.getVaultPath() === VAULT_PATH, '锁定后选择回到正式库');
  ok(plugin.isReadOnlyCopy() === false, '锁定后只读态复位');
  fileStore.delete(conflictCopy);

  // 19e) 嵌套冲突副本（xxx.conflict-a.conflict-b.enc）也能被枚举，且按时间倒序
  const oldCopy = VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200101-000000.enc';
  const nestedCopy =
    VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200101-000000.conflict-20200102-000000.enc';
  fileStore.set(oldCopy, fileStore.get(VAULT_PATH));
  fileStore.set(nestedCopy, fileStore.get(VAULT_PATH));
  await plugin.lock();
  await plugin.scanVaultSources();
  ok(plugin.vaultSources.length === 3, '正式库与两层/单层冲突副本都被枚举');
  ok(plugin.vaultSources.indexOf(nestedCopy) >= 0, '嵌套冲突副本进入候选列表');
  ok(plugin.vaultSources[0] === VAULT_PATH, '存在嵌套副本时默认仍指向正式库');
  ok(plugin.selectedVaultPath === '', '嵌套副本不会被自动选中');
  ok(
    plugin.vaultSources.indexOf(nestedCopy) < plugin.vaultSources.indexOf(oldCopy),
    '候选副本按冲突时间倒序'
  );
  fileStore.delete(oldCopy);
  fileStore.delete(nestedCopy);

  // 20) 笔记 / 表格 / 链接（0.2.0）
  plugin.lock();
  restart();
  // 20a) 旧数据（只有 entries，没有 notes / contentVersion）读取后自动补默认笔记
  const noNotesEnvelope = await buildV2EnvelopeWithoutNotes(MASTER, [
    {
      id: 'legacy-note-1',
      name: 'Legacy Note Entry',
      type: 'note',
      content: SECRET_THREE,
      tags: [],
      note: '',
      createdAt: '',
      updatedAt: '',
    },
  ]);
  restoreVault(JSON.stringify(noNotesEnvelope, null, 2));
  ok((await unlockFresh(MASTER)) === true, '旧结构（无 notes）信封可解锁');
  ok(plugin.notes.length === 1, '旧结构读取后自动补一篇默认笔记');
  ok(
    plugin.notes[0].id === 'note-primary' && plugin.notes[0].title === '我的密钥',
    '默认笔记 id 与标题符合约定'
  );
  ok(plugin.contentVersion === 1, '旧结构 contentVersion 缺省为兼容版本 1');

  // 20b) 准备两个条目，供引用语法使用
  await plugin.addEntry({ name: 'GitHub', type: 'password', content: SECRET_ONE, tags: [], note: '' });
  await plugin.addEntry({ name: 'API Key', type: 'api-key', content: SECRET_TWO, tags: [], note: '' });
  ok(plugin.entries.length === 3, '准备条目完成（旧条目 + 两个新条目）');

  const NOTE_BODY_MARKER = 'NOTE-BODY-MARKER-9F3A';
  const NOTE_SOURCE = [
    '# 我的密钥',
    '',
    '段落：这是 **加粗** 与 `行内代码`，还有一个安全链接 [官网](https://example.com)。',
    'HTML 原样显示：<script>alert(1)</script>',
    '',
    '## 账号表',
    '',
    '| 名称 | 账号 | 密码 |',
    '| :--- | ---: | :---: |',
    '| GitHub | {{GitHub.账号}} | {{GitHub.密码}} |',
    '| 缺失 | {{Missing.密码}} | PLAIN-TABLE-VALUE |',
    '',
    '- 列表项一',
    '- 列表项二',
    '1. 有序一',
    '2. 有序二',
    '',
    '危险链接：[危险](javascript:alert(1))',
    '本地链接：[本地](file:///etc/passwd)',
    '',
    NOTE_BODY_MARKER,
  ].join('\n');

  ok((await plugin.saveNote('note-primary', NOTE_SOURCE)) !== undefined, '笔记保存调用成功');
  ok(plugin.notes[0].body === NOTE_SOURCE, '保存后内存中的笔记体已更新');
  ok(plugin.notes[0].updatedAt !== '', '保存后写入 updatedAt');

  const notePayload = await plugin.decryptEnvelope(plugin.parseEnvelope(goodText()), plugin.sessionKey);
  ok(notePayload.contentVersion === 2, '写盘载荷 contentVersion 升级为 2');
  ok(Array.isArray(notePayload.notes) && notePayload.notes.length === 1, '密文中包含 notes 数组');
  ok(notePayload.notes[0].body === NOTE_SOURCE, '笔记体完整写入密文');
  ok(notePayload.entries.length === 3, '保存笔记不影响既有 entries');
  const noteCipherText = goodText();
  ok(noteCipherText.indexOf(NOTE_BODY_MARKER) < 0, '负向：密文不含笔记明文标记');
  ok(noteCipherText.indexOf(SECRET_ONE) < 0 && noteCipherText.indexOf(SECRET_TWO) < 0, '负向：密文不含条目明文');

  const mainSource = fs.readFileSync(MAIN, 'utf8');
  ok(!/\.innerHTML\s*=/.test(mainSource), '负向：渲染代码不使用 innerHTML');
  ok(mainSource.indexOf('insertAdjacentHTML') < 0, '负向：渲染代码不使用 insertAdjacentHTML');

  // 20c) 视图：表格 / 笔记切换
  view.render();
  ok(!!findButton(view.contentEl, '表格') && !!findButton(view.contentEl, '笔记'), '顶部显示表格 / 笔记切换');
  findButton(view.contentEl, '笔记').click();
  ok(view.mode === 'notes', '点击「笔记」进入笔记模式');
  ok(view.contentEl.querySelector('.xsv-notes') !== null, '渲染笔记布局');
  ok(!!findButton(view.contentEl, '我的密钥'), '笔记列表显示默认笔记标题');
  const noteText = textOf(view.contentEl);
  ok(noteText.indexOf('NOTE-BODY-MARKER') >= 0, '笔记正文已渲染');
  ok(noteText.indexOf('**加粗**') < 0 && noteText.indexOf('| 名称 |') < 0, '负向：渲染区不出现 Markdown 源码标记');

  // 20d) 管道表格：真实 table、列对齐、单元格内容
  const mdTables = findAll(view.contentEl, (el) => el.tagName === 'TABLE');
  ok(mdTables.length === 1 && mdTables[0].hasClass('xsv-md-table'), '管道表格渲染为真实 table');
  const headerCells = findAll(mdTables[0], (el) => el.tagName === 'TH');
  ok(headerCells.length === 3, '表头为 3 列');
  ok(
    textOf(headerCells[0]).trim() === '名称' &&
      textOf(headerCells[1]).trim() === '账号' &&
      textOf(headerCells[2]).trim() === '密码',
    '表头文本正确'
  );
  ok(headerCells[0].style.textAlign === 'left', '左对齐列按 :--- 对齐');
  ok(headerCells[1].style.textAlign === 'right', '右对齐列按 ---: 对齐');
  ok(headerCells[2].style.textAlign === 'center', '居中列按 :---: 对齐');
  const bodyCells = findAll(mdTables[0], (el) => el.tagName === 'TD');
  ok(bodyCells.length === 6, '两行数据渲染出 6 个单元格');
  ok(
    textOf(mdTables[0]).indexOf('PLAIN-TABLE-VALUE') >= 0,
    '表格中的明文值照常显示'
  );

  // 20e) 引用语法：{name} / {name.密码} / {name.账号}
  const refButtons = findAll(view.contentEl, (el) => el.tagName === 'BUTTON' && el.hasClass('xsv-ref'));
  ok(refButtons.length === 2, '两个有效引用各渲染为掩码按钮');
  ok(refButtons.every((el) => String(el.textContent).indexOf('••••••') === 0), '引用按钮只显示掩码，不含值');
  ok(noteText.indexOf(SECRET_ONE) < 0, '负向：引用值不进入 DOM 文本');
  clipboard = '';
  refButtons[1].click();
  ok(clipboard === SECRET_ONE, '点击 {{GitHub.密码}} 复制对应密码');
  clipboard = '';
  refButtons[0].click();
  ok(clipboard === 'GitHub', '点击 {{GitHub.账号}} 复制条目的账号值');

  const missingRefs = findAll(view.contentEl, (el) => el.hasClass('xsv-ref-missing'));
  ok(missingRefs.length === 1, '引用缺失渲染为独立提示');
  ok(
    textOf(missingRefs[0]).indexOf('引用缺失') >= 0 && textOf(missingRefs[0]).indexOf('Missing.密码') >= 0,
    '引用缺失文案包含名称'
  );

  // 20f) 链接白名单：只有 http/https 可点击
  const anchors = findAll(view.contentEl, (el) => el.tagName === 'A');
  ok(anchors.length === 1, '负向：只有 http/https 链接生成可点击元素');
  ok(anchors[0].getAttribute('href') === 'https://example.com', 'http/https 链接保留原地址');
  ok(noteText.indexOf('javascript:alert(1)') >= 0, '负向：javascript: 链接按纯文本显示');
  ok(noteText.indexOf('file:///etc/passwd') >= 0, '负向：file:// 链接按纯文本显示');
  ok(
    !findAll(view.contentEl, (el) => el.tagName === 'SCRIPT').length,
    '负向：Markdown 中的脚本标签不会变成真实节点'
  );

  // 20g) 其它 Markdown 结构
  ok(findAll(view.contentEl, (el) => el.tagName === 'H2').length === 1, '二级标题渲染为 h2');
  ok(findAll(view.contentEl, (el) => el.tagName === 'STRONG').length >= 1, '粗体渲染为 strong');
  ok(findAll(view.contentEl, (el) => el.tagName === 'CODE').length >= 1, '行内代码渲染为 code');
  ok(findAll(view.contentEl, (el) => el.tagName === 'UL' && el.children.length === 2).length === 1, '无序列表两项');
  ok(findAll(view.contentEl, (el) => el.tagName === 'OL' && el.children.length === 2).length === 1, '有序列表两项');

  // 20h) 编辑态：等宽 textarea 直接写 Markdown，保存走原子写链路
  const editNoteButton = findButton(view.contentEl, '编辑笔记');
  ok(!!editNoteButton, '笔记模式提供编辑入口');
  editNoteButton.click();
  ok(view.noteEditing === true, '点击后进入编辑态');
  const editor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  ok(!!editor && editor.hasClass('xsv-note-editor'), '编辑态使用等宽 textarea');
  ok(editor.value === NOTE_SOURCE, 'textarea 显示完整 Markdown 源码');
  editor.value = NOTE_SOURCE + '\n\n追加-EDIT-MARKER-2B7C';
  editor.fire('input');
  findButton(view.contentEl, '保存笔记').click();
  await waitFor(() => plugin.notes[0].body.indexOf('追加-EDIT-MARKER-2B7C') >= 0, '保存笔记');
  ok(view.noteEditing === false && view.noteDraft === null, '保存后退出编辑态并丢弃草稿');
  ok(!findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA').length, '保存后 textarea 已移除');
  const editedPayload = await plugin.decryptEnvelope(plugin.parseEnvelope(goodText()), plugin.sessionKey);
  ok(editedPayload.notes[0].body.indexOf('追加-EDIT-MARKER-2B7C') >= 0, '编辑后的笔记已加密落盘');
  ok(goodText().indexOf('追加-EDIT-MARKER-2B7C') < 0, '负向：编辑后的密文不含笔记明文');

  // 20i) 取消编辑不写盘
  findButton(view.contentEl, '编辑笔记').click();
  const cancelEditor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  cancelEditor.value = '取消-不应落盘-CANCEL-MARKER';
  cancelEditor.fire('input');
  findButton(view.contentEl, '取消编辑').click();
  ok(view.noteEditing === false && view.noteDraft === null, '取消编辑后丢弃草稿');
  ok(plugin.notes[0].body.indexOf('CANCEL-MARKER') < 0, '负向：取消编辑不改内存笔记');
  ok(goodText().indexOf('CANCEL-MARKER') < 0, '负向：取消编辑不写盘');

  // 20j) 锁定后笔记区、编辑器、列表与草稿全部清空
  const noteTextBeforeLock = textOf(view.contentEl);
  ok(noteTextBeforeLock.indexOf(NOTE_BODY_MARKER) >= 0, '锁定前笔记正文可见');
  plugin.lock();
  view.render();
  const lockedText = textOf(view.contentEl);
  ok(lockedText.indexOf(NOTE_BODY_MARKER) < 0, '锁定后笔记区无明文');
  ok(lockedText.indexOf('追加-EDIT-MARKER-2B7C') < 0, '锁定后编辑内容无残留');
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-notes')).length, '锁定后笔记列表被移除');
  ok(!findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA').length, '锁定后编辑器被移除');
  ok(view.noteDraft === null && view.noteEditing === false, '锁定后笔记草稿被丢弃');
  ok(plugin.notes.length === 0, '锁定后内存中的 notes 被清空');

  // 20k) 只读冲突副本：笔记只能看，保存被拒且文件字节不变
  const canonicalNoteText = fileStore.get(VAULT_PATH);
  ok((await plugin.unlock(MASTER)) === true, '重新解锁正式库');
  const readOnlyCopy = VAULT_PATH.replace(/\.enc$/i, '') + '.conflict-20200103-000000.enc';
  fileStore.set(readOnlyCopy, canonicalNoteText);
  plugin.lock();
  await plugin.scanVaultSources();
  plugin.selectedVaultPath = readOnlyCopy;
  ok((await plugin.unlock(MASTER)) === true, '只读副本可解锁');
  view.mode = 'notes';
  view.render();
  ok(plugin.isReadOnlyCopy() === true, '查看副本时进入只读态');
  ok(!findButton(view.contentEl, '编辑笔记'), '只读副本下不提供笔记编辑入口');
  ok(String(textOf(view.contentEl)).indexOf('NOTE-BODY-MARKER') >= 0, '只读副本下笔记仍可查看');
  const copyBytesBefore = fileStore.get(readOnlyCopy);
  const canonicalBytesBefore = fileStore.get(VAULT_PATH);
  await rejects(
    plugin.saveNote(plugin.notes[0].id, '只读副本写入尝试'),
    '只读',
    '负向：只读副本下笔记保存被拒'
  );
  ok(fileStore.get(readOnlyCopy) === copyBytesBefore, '只读副本文件字节未变（笔记写入）');
  ok(fileStore.get(VAULT_PATH) === canonicalBytesBefore, '正式库文件字节未变（笔记写入）');
  plugin.lock();
  await plugin.scanVaultSources();
  fileStore.delete(readOnlyCopy);
  ok(plugin.isReadOnlyCopy() === false && plugin.selectedVaultPath === '', '锁定后只读态复位');

  // 21) 0.2.1 可用性增强
  ok((await plugin.unlock(MASTER)) === true, '解锁以测试 0.2.1');
  await plugin.saveNote('note-primary', '');
  view.mode = 'table';
  view.noteEmptyHintShown = false;
  view.render();
  const tableTab = findButton(view.contentEl, '表格');
  const notesTab = findButton(view.contentEl, '笔记');
  ok(!!tableTab && tableTab.hasClass('xsv-mode-tab-table'), '表格切换按钮带独立图标类');
  ok(!!notesTab && notesTab.hasClass('xsv-mode-tab-notes'), '笔记切换按钮带独立图标类');
  ok(tableTab.hasClass('xsv-mode-tab-active') && !notesTab.hasClass('xsv-mode-tab-active'), '当前模式选中态正确');
  notices.length = 0;
  notesTab.click();
  ok(view.mode === 'notes', '点击笔记进入笔记模式');
  const notesTabAfter = findButton(view.contentEl, '笔记');
  const tableTabAfter = findButton(view.contentEl, '表格');
  ok(
    notesTabAfter.hasClass('xsv-mode-tab-active') && !tableTabAfter.hasClass('xsv-mode-tab-active'),
    '笔记模式选中态强化'
  );
  ok(notices.some((message) => message.indexOf('这里是笔记模式') >= 0), '首次切到空笔记模式给一次性提示');
  findButton(view.contentEl, '表格').click();
  findButton(view.contentEl, '笔记').click();
  ok(
    notices.filter((message) => message.indexOf('这里是笔记模式') >= 0).length === 1,
    '一次性提示不重复'
  );

  // 21a) 空态引导 + 示例表格按钮（不自动保存）
  const guide = findAll(view.contentEl, (el) => el.hasClass('xsv-note-guide'))[0];
  ok(!!guide, '空笔记显示引导块');
  ok(textOf(guide).indexOf('从这里开始写账号表') >= 0, '引导块说明可见');
  const sampleButton = findButton(view.contentEl, '插入示例表格');
  ok(!!sampleButton, '空态提供插入示例表格按钮');
  sampleButton.click();
  ok(view.noteEditing === true, '点击示例后进入编辑态');
  const sampleEditor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  const sampleNames = plugin.entries.slice(0, 2).map((entry) => entry.name);
  ok(sampleEditor.value.indexOf('| 名称 | 账号 | 密码 |') >= 0, '示例包含三列表头');
  ok(
    sampleEditor.value.indexOf('{{' + sampleNames[0] + '.账号}}') >= 0 &&
      sampleEditor.value.indexOf('{{' + sampleNames[0] + '.密码}}') >= 0,
    '示例使用当前真实条目名生成引用'
  );
  ok(plugin.notes[0].body === '', '负向：示例插入不自动保存');
  findButton(view.contentEl, '保存笔记').click();
  await waitFor(() => plugin.notes[0].body.indexOf('| 名称 | 账号 | 密码 |') >= 0, '保存示例笔记');

  // 21b) 条目内容按 Markdown 渲染；自引用降级为引用缺失
  const apiKeyEntry = plugin.entries.filter((entry) => entry.name === 'API Key')[0];
  ok(!!apiKeyEntry, '找到用于条目渲染的 API Key');
  await plugin.updateEntry(apiKeyEntry.id, {
    name: 'API Key',
    type: 'api-key',
    tags: [],
    content: '| 字段 | 值 |\n| --- | --- |\n| 自引用 | {{API Key.密码}} |\n| 其它 | {{GitHub.密码}} |',
    note: '',
  });
  view.mode = 'table';
  view.revealed.add(apiKeyEntry.id);
  view.render();
  const entryContent = findAll(view.contentEl, (el) => el.hasClass('xsv-content'))[0];
  ok(!!entryContent, '显示的条目内容区存在');
  const entryTable = findAll(entryContent, (el) => el.tagName === 'TABLE')[0];
  ok(!!entryTable && entryTable.hasClass('xsv-md-table'), '条目内容中的管道表格渲染为真实 table');
  const selfMissing = findAll(entryContent, (el) => el.hasClass('xsv-ref-missing'));
  ok(selfMissing.length === 1 && textOf(selfMissing[0]).indexOf('API Key') >= 0, '负向：自引用降级为引用缺失');
  const selfNote = findAll(entryContent, (el) => el.hasClass('xsv-ref-selfnote'))[0];
  ok(!!selfNote && textOf(selfNote).indexOf('不能引用自身') >= 0, '自引用给出灰色说明');
  const entryRefButtons = findAll(entryContent, (el) => el.hasClass('xsv-ref'));
  ok(
    !entryRefButtons.some((el) => String(el.textContent).indexOf('API Key') >= 0),
    '负向：自引用不生成可复制按钮'
  );
  ok(entryRefButtons.length === 1, '条目内容中的跨条目引用生成一个按钮');
  const crossRef = entryRefButtons[0];
  ok(!!crossRef && String(crossRef.textContent).indexOf('GitHub') >= 0, '条目内容可引用其它条目并掩码显示');
  ok(String(textOf(entryContent)).indexOf(SECRET_TWO) < 0, '负向：条目引用值不进入 DOM 文本');
  view.revealed.clear();

  // 21c) 引用缺失可点击创建条目：取消路径 + 确认路径
  await plugin.saveNote('note-primary', '{{Nope.密码}}');
  view.mode = 'notes';
  view.render();
  const missingAction = findAll(view.contentEl, (el) => el.hasClass('xsv-ref-missing-action'))[0];
  ok(!!missingAction && missingAction.tagName === 'BUTTON', '引用缺失渲染为可点击元素');
  const entryCountBefore = plugin.entries.length;
  missingAction.click();
  const confirmBar = findAll(view.contentEl, (el) => el.hasClass('xsv-ref-create-confirm'))[0];
  ok(!!confirmBar, '点击后出现创建确认条');
  ok(textOf(confirmBar).indexOf('是否创建同名条目') >= 0 && textOf(confirmBar).indexOf('Nope') >= 0, '确认文案包含条目名');
  ok(plugin.entries.length === entryCountBefore, '负向：确认前不自动创建条目');
  findButton(confirmBar, '取消').click();
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-ref-create-confirm')).length, '取消后确认条消失');
  ok(plugin.entries.length === entryCountBefore, '负向：取消后不创建条目');

  findAll(view.contentEl, (el) => el.hasClass('xsv-ref-missing-action'))[0].click();
  findButton(view.contentEl, '创建条目').click();
  const openedModals = Array.from(plugin.openModals);
  const refCreateModal = openedModals[openedModals.length - 1];
  ok(!!refCreateModal, '确认后打开现有新增条目表单');
  const refModalInputs = findAll(refCreateModal.contentEl, (el) => el.tagName === 'INPUT');
  const refModalSelects = findAll(refCreateModal.contentEl, (el) => el.tagName === 'SELECT');
  ok(refModalInputs[0] && refModalInputs[0].value === 'Nope', '新增表单预填条目名（去掉 .密码 字段）');
  ok(refModalSelects[0] && refModalSelects[0].value === 'password', '新增表单按字段预填密码类型');
  refCreateModal.close();
  ok(plugin.entries.length === entryCountBefore, '负向：只打开表单，不静默写入');

  // 21d) 示例插入不重复：已有内容先选择追加/替换
  await plugin.saveNote('note-primary', '已有内容-EXISTING');
  view.render();
  findButton(view.contentEl, '编辑笔记').click();
  const dupEditor = findAll(view.contentEl, (el) => el.tagName === 'TEXTAREA')[0];
  findButton(view.contentEl, '插入示例表格').click();
  const choice = findAll(view.contentEl, (el) => el.hasClass('xsv-sample-choice'))[0];
  ok(!!choice && choice.style.display !== 'none', '已有内容时先显示追加/替换选择');
  ok(dupEditor.value.indexOf('| 名称 | 账号 | 密码 |') < 0, '负向：未选择前不插入示例');
  ok(plugin.notes[0].body === '已有内容-EXISTING', '负向：未选择前不改内存笔记');
  findButton(view.contentEl, '追加到末尾').click();
  const headerCount = (dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \|/g) || []).length;
  ok(headerCount === 1, '追加后示例只出现一次');
  ok(dupEditor.value.indexOf('已有内容-EXISTING') === 0, '追加保留原有内容');
  ok(choice.style.display === 'none', '选择后隐藏选择条');
  findButton(view.contentEl, '插入示例表格').click();
  ok(choice.style.display !== 'none', '再次点击示例重新出现选择');
  const headerCount2 = (dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \|/g) || []).length;
  ok(headerCount2 === 1, '负向：第二次点击本身不造成重复');
  findButton(choice, '取消').click();
  ok(choice.style.display === 'none', '取消追加后保留原有内容');
  ok((dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \|/g) || []).length === 1, '取消后仍只有一份示例');
  findButton(view.contentEl, '插入示例表格').click();
  findButton(view.contentEl, '替换全文').click();
  ok(dupEditor.value.indexOf('已有内容-EXISTING') < 0, '替换全文移除原内容');
  ok((dupEditor.value.match(/\| 名称 \| 账号 \| 密码 \|/g) || []).length === 1, '替换后只有一份示例');

  // 21e) 编辑态列出可用条目名（仅名称，不含值），过长折叠
  const namesBar = findAll(view.contentEl, (el) => el.hasClass('xsv-ref-names'))[0];
  ok(!!namesBar, '编辑态显示可用条目名提示条');
  const namesText = textOf(namesBar);
  ok(namesText.indexOf('GitHub') >= 0 && namesText.indexOf('API Key') >= 0, '提示条列出当前条目名');
  ok(namesText.indexOf(SECRET_ONE) < 0 && namesText.indexOf(SECRET_TWO) < 0, '负向：提示条不显示任何值');
  const originalEntries = plugin.entries;
  plugin.entries = originalEntries.concat(
    Array.from({ length: 7 }, (unused, index) => ({
      id: 'tmp-' + index,
      name: 'TMP-' + index,
      type: 'password',
      content: 'x',
      tags: [],
      note: '',
    }))
  );
  view.render();
  const collapsedBar = findAll(view.contentEl, (el) => el.hasClass('xsv-ref-names'))[0];
  ok(textOf(collapsedBar).indexOf('共 10 个') >= 0, '条目名过多时折叠为数量');
  ok(!textOf(collapsedBar).includes('TMP-0'), '负向：折叠时不展开全部名称');
  findButton(collapsedBar, '展开查看').click();
  const expandedBar = findAll(view.contentEl, (el) => el.hasClass('xsv-ref-names'))[0];
  ok(textOf(expandedBar).indexOf('TMP-0') >= 0, '展开后显示全部条目名');
  plugin.entries = originalEntries;
  view.render();
  findButton(view.contentEl, '取消编辑').click();

  // 21f) 条目保存后的笔记提示只弹一次
  notices.length = 0;
  plugin.markdownHintShown = false;
  ok(plugin.maybeHintNoteContent('普通密码 abc123') === false, '负向：普通内容不触发笔记提示');
  ok(plugin.maybeHintNoteContent('| a | b |\n| --- | --- |\n| 1 | 2 |') === true, '管道表格内容触发提示');
  ok(notices.some((message) => message.indexOf('笔记模式') >= 0), '提示文案指向笔记模式');
  ok(plugin.maybeHintNoteContent('{{GitHub.密码}}') === false, '负向：同一会话不重复提示');
  ok(notices.filter((message) => message.indexOf('笔记模式') >= 0).length === 1, '提示只弹一次');
  plugin.markdownHintShown = false;
  ok(plugin.maybeHintNoteContent('{{GitHub.密码}}') === true, '引用内容同样触发提示');

  // 21g) 锁定后新增的引用/示例状态一并清空
  view.mode = 'notes';
  view.noteEditing = true;
  view.noteDraft = '示例草稿-DRAFT-MARKER';
  view.pendingRefCreate = { name: 'Nope', field: '密码' };
  view.render();
  plugin.lock();
  ok(view.noteEditing === false && view.noteDraft === null, '锁定后草稿被丢弃（0.2.1）');
  ok(view.pendingRefCreate === null, '锁定后待创建引用状态被清空');
  ok(String(textOf(view.contentEl)).indexOf('DRAFT-MARKER') < 0, '锁定后不残留示例草稿');
  ok(!findAll(view.contentEl, (el) => el.hasClass('xsv-sample-choice')).length, '锁定后追加/替换选择条被移除');

  // 22) crypto.subtle 不可用时明确报错
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
