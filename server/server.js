'use strict';
/* 刷题宝 · 自建云同步服务（零依赖，Node 18+）
 * 复刻 Supabase 用到的 5 个接口，前端只需把地址指向本服务。
 *   POST /auth/v1/signup                         注册并登录
 *   POST /auth/v1/token?grant_type=password       登录
 *   POST /auth/v1/token?grant_type=refresh_token  续期
 *   GET  /rest/v1/sync_data                       拉取全部同步键
 *   POST /rest/v1/sync_data                       上传（merge upsert）
 * 同时托管站点静态文件，保证前后端同源、无跨域问题。
 */
const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 5002);
const HOST = process.env.HOST || '0.0.0.0';
const API_KEY = process.env.SYNC_API_KEY || '';        // 可选：留空则不校验 apikey
const ROOT = path.resolve(__dirname, '..');            // 站点根目录（index.html 所在）
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const ACCESS_TTL = 12 * 3600 * 1000;
const REFRESH_TTL = 90 * 24 * 3600 * 1000;
const MAX_BODY = 64 * 1024 * 1024;                     // 题库可能几 MB，放宽到 64MB

/* ---------- 存储 ---------- */
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: {}, emails: {}, tokens: {}, refresh: {}, rows: {} };
try {
  const raw = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  ['users', 'emails', 'tokens', 'refresh', 'rows'].forEach(function (k) { db[k] = raw[k] || {}; });
} catch (e) { /* 首次启动，用空库 */ }

let writeChain = Promise.resolve();
function save() {
  writeChain = writeChain.then(function () {
    const now = Date.now();
    Object.keys(db.tokens).forEach(function (t) { if (db.tokens[t].exp < now) delete db.tokens[t]; });
    Object.keys(db.refresh).forEach(function (t) { if (db.refresh[t].exp < now) delete db.refresh[t]; });
    return fsp.writeFile(DB_FILE + '.tmp', JSON.stringify(db))
      .then(function () { return fsp.rename(DB_FILE + '.tmp', DB_FILE); })
      .catch(function (e) {
        // Windows 下目标文件被占用（杀毒/备份/并发读）时 rename 会失败，
        // 回退为直接覆盖写，避免续期 token 等最新状态静默丢失（重启后回到旧 token）
        console.error('[save] rename 失败，回退直写:', e.message);
        return fsp.writeFile(DB_FILE, JSON.stringify(db));
      });
  }).catch(function (e) { console.error('[save]', e.message); });
  return writeChain;
}

/* ---------- 账号 / 令牌 ---------- */
function hashPass(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return { salt: salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function verifyPass(pw, u) {
  const h = crypto.scryptSync(pw, u.salt, 64);
  const ref = Buffer.from(u.hash, 'hex');
  return h.length === ref.length && crypto.timingSafeEqual(h, ref);
}
function newTok() { return crypto.randomBytes(32).toString('hex'); }
function issue(uid) {
  const at = newTok(), rt = newTok(), now = Date.now();
  db.tokens[at] = { uid: uid, exp: now + ACCESS_TTL };
  db.refresh[rt] = { uid: uid, exp: now + REFRESH_TTL };
  return {
    access_token: at, refresh_token: rt, token_type: 'bearer',
    expires_in: Math.floor(ACCESS_TTL / 1000),
    user: { id: uid, email: (db.users[uid] || {}).email || '' }
  };
}
function uidOf(req) {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  if (!m) return null;
  const s = db.tokens[m[1]];
  if (!s) return null;
  if (s.exp < Date.now()) { delete db.tokens[m[1]]; return null; }
  return s.uid;
}

/* ---------- HTTP 辅助 ---------- */
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
}
function json(res, code, obj) {
  cors(res);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function err(res, code, msg) { json(res, code, { error: msg, message: msg }); }
function body(req) {
  return new Promise(function (resolve, reject) {
    let n = 0; const parts = [];
    req.on('data', function (c) {
      n += c.length;
      if (n > MAX_BODY) { reject(new Error('payload too large')); req.destroy(); return; }
      parts.push(c);
    });
    req.on('end', function () {
      const s = Buffer.concat(parts).toString('utf8').trim();
      if (!s) return resolve({});
      try { resolve(JSON.parse(s)); } catch (e) { reject(new Error('invalid json')); }
    });
    req.on('error', reject);
  });
}

/* ---------- 接口 ---------- */
const fails = {};   // 简易限流：同 IP 连续失败 15 次后冷却 10 分钟
function throttled(ip) {
  const f = fails[ip];
  if (!f) return false;
  if (Date.now() - f.t > 600000) { delete fails[ip]; return false; }
  return f.n >= 15;
}
function bumpFail(ip) {
  const f = fails[ip];
  if (!f || Date.now() - f.t > 600000) fails[ip] = { n: 1, t: Date.now() };
  else f.n++;
}

function handleSignup(req, res, b) {
  const email = String(b.email || '').trim().toLowerCase();
  const pass = String(b.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err(res, 400, '邮箱格式不正确');
  if (pass.length < 6) return err(res, 400, '密码至少 6 位');
  if (db.emails[email]) return err(res, 400, '该邮箱已注册，请直接登录');
  const uid = crypto.randomUUID();
  const h = hashPass(pass);
  db.users[uid] = { id: uid, email: email, salt: h.salt, hash: h.hash, createdAt: new Date().toISOString() };
  db.emails[email] = uid;
  db.rows[uid] = db.rows[uid] || {};
  const sess = issue(uid);
  return save().then(function () { json(res, 201, sess); });
}

function handleToken(req, res, b, q) {
  const grant = q.get('grant_type') || 'password';
  if (grant === 'refresh_token') {
    const s = db.refresh[String(b.refresh_token || '')];
    if (!s || s.exp < Date.now()) return err(res, 400, '登录已过期，请重新登录');
    delete db.refresh[b.refresh_token];
    const sess = issue(s.uid);
    return save().then(function () { json(res, 200, sess); });
  }
  const email = String(b.email || '').trim().toLowerCase();
  const uid = db.emails[email];
  const u = uid && db.users[uid];
  if (!u || !verifyPass(String(b.password || ''), u)) {
    bumpFail(req.socket.remoteAddress || '?');
    return err(res, 400, '邮箱或密码错误');
  }
  const sess = issue(u.id);
  return save().then(function () { json(res, 200, sess); });
}

function handlePull(req, res) {
  const uid = uidOf(req);
  if (!uid) return err(res, 401, '未登录或登录已过期');
  const rows = db.rows[uid] || {};
  const out = Object.keys(rows).map(function (k) {
    return { user_id: uid, data_key: k, payload: rows[k].payload, updated_at: rows[k].updated_at };
  });
  json(res, 200, out);
}

function handlePush(req, res, b) {
  const uid = uidOf(req);
  if (!uid) return err(res, 401, '未登录或登录已过期');
  const list = Array.isArray(b) ? b : [b];
  db.rows[uid] = db.rows[uid] || {};
  const saved = [];
  list.forEach(function (r) {
    if (!r || typeof r.data_key !== 'string') return;
    // 统一使用服务器时间作为 updated_at，避免各设备时钟偏差导致新旧误判
    const ts = new Date().toISOString();
    db.rows[uid][r.data_key] = { payload: r.payload === undefined ? {} : r.payload, updated_at: ts };
    saved.push({ user_id: uid, data_key: r.data_key, payload: db.rows[uid][r.data_key].payload, updated_at: ts });
  });
  return save().then(function () { json(res, 201, saved); });
}

/* ---------- 静态站点 ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.split('?')[0]);
  if (p === '/' || p === '') p = '/index.html';
  const rel = p.replace(/^\/+/, '');
  if (rel.startsWith('.') || rel.startsWith('server/') || rel.startsWith('server\\') || rel.includes('..')) {
    return err(res, 403, 'forbidden');
  }
  const file = path.join(ROOT, rel);
  fs.readFile(file, function (e, buf) {
    if (e) { err(res, 404, 'not found'); return; }
    cors(res);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' });
    res.end(buf);
  });
}

/* ---------- 主循环 ---------- */
const server = http.createServer(function (req, res) {
  const u = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  const p = u.pathname;
  if (req.method === 'OPTIONS') { cors(res); res.writeHead(204); return res.end(); }

  if (p === '/health') return json(res, 200, { ok: true, users: Object.keys(db.users).length });
  // 接口需要 apikey（服务端未设置 SYNC_API_KEY 时不校验），静态站点不校验
  if ((p.startsWith('/auth/') || p.startsWith('/rest/')) && API_KEY && req.headers.apikey !== API_KEY) {
    return err(res, 401, 'apikey 不正确');
  }

  if (p === '/auth/v1/signup' && req.method === 'POST') {
    if (throttled(req.socket.remoteAddress || '?')) return err(res, 429, '尝试过于频繁，请稍后再试');
    return body(req).then(function (b) { handleSignup(req, res, b); }).catch(function (e) { err(res, 400, e.message); });
  }
  if (p === '/auth/v1/token' && req.method === 'POST') {
    if (throttled(req.socket.remoteAddress || '?')) return err(res, 429, '尝试过于频繁，请稍后再试');
    return body(req).then(function (b) { handleToken(req, res, b, u.searchParams); }).catch(function (e) { err(res, 400, e.message); });
  }
  if (p === '/auth/v1/logout' && req.method === 'POST') {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    if (m) delete db.tokens[m[1]];
    return save().then(function () { json(res, 200, {}); });
  }
  if (p === '/rest/v1/sync_data' && req.method === 'GET') return handlePull(req, res);
  if (p === '/rest/v1/sync_data' && req.method === 'POST') {
    return body(req).then(function (b) { handlePush(req, res, b); }).catch(function (e) { err(res, 400, e.message); });
  }
  if (p.startsWith('/auth/') || p.startsWith('/rest/')) return err(res, 404, 'no such route');

  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, p);
  err(res, 405, 'method not allowed');
});

server.requestTimeout = 120000;
server.headersTimeout = 130000;
server.listen(PORT, HOST, function () {
  console.log('刷题宝同步服务已启动: http://' + (HOST === '0.0.0.0' ? '本机IP' : HOST) + ':' + PORT);
  console.log('站点目录: ' + ROOT);
  console.log('数据文件: ' + DB_FILE);
  console.log('apikey 校验: ' + (API_KEY ? '已开启' : '未开启'));
});
