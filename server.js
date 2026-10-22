'use strict';
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ───────────────────────── Настройки ─────────────────────────
const env = process.env;
const PORT = Number(env.PORT) || 3000;
const SITE_URL = (env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SHOP_NAME = env.SHOP_NAME || 'Папа Пиццоли';
const DELIVERY_FEE = Number(env.DELIVERY_FEE) || 0;
const FREE_FROM = Number(env.FREE_DELIVERY_FROM) || 0;
const DEMO = env.DEMO_PAYMENTS === 'true';
const PAYME = { merchant: env.PAYME_MERCHANT_ID, key: env.PAYME_KEY, test: env.PAYME_TEST === 'true' };
const CLICK = { service: env.CLICK_SERVICE_ID, merchant: env.CLICK_MERCHANT_ID, secret: env.CLICK_SECRET_KEY };
const paymeOn = !!(PAYME.merchant && PAYME.key);
const clickOn = !!(CLICK.service && CLICK.merchant && CLICK.secret);

let JWT_SECRET = env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 16) {
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('⚠ JWT_SECRET не задан в .env: админ будет выходить из системы при каждом перезапуске сервера.');
}
if (!env.ADMIN_PASSWORD_HASH) console.warn('⚠ ADMIN_PASSWORD_HASH не задан: вход в админку отключён. Выполните: npm run hash -- "ВашПароль"');

// ───────────────────────── База данных ─────────────────────────
const dbFile = env.DB_FILE || path.join(__dirname, 'data', 'pizza.db');
fs.mkdirSync(path.dirname(dbFile), { recursive: true });
const db = new Database(dbFile);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '',
  category TEXT NOT NULL, price INTEGER NOT NULL, sizes TEXT, image TEXT DEFAULT '', available INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS addons (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price INTEGER NOT NULL, available INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS promos (
  id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, percent INTEGER NOT NULL, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL, customer_name TEXT, phone TEXT, address TEXT,
  comment TEXT, delivery_type TEXT, items TEXT, subtotal INTEGER, discount INTEGER, delivery_fee INTEGER,
  total INTEGER, promo TEXT, pay_method TEXT, payment_status TEXT, status TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS payme_tx (
  id TEXT PRIMARY KEY, order_id INTEGER, amount INTEGER, state INTEGER, time INTEGER,
  create_time INTEGER, perform_time INTEGER DEFAULT 0, cancel_time INTEGER DEFAULT 0, reason INTEGER);
CREATE TABLE IF NOT EXISTS click_tx (
  id INTEGER PRIMARY KEY AUTOINCREMENT, click_trans_id TEXT UNIQUE, order_id INTEGER, amount REAL, state INTEGER DEFAULT 0);
`);

if (!db.prepare('SELECT COUNT(*) c FROM products').get().c) {
  const sz = (a, b, c) => JSON.stringify([{ name: '25 см', price: a }, { name: '30 см', price: b }, { name: '35 см', price: c }]);
  const ins = db.prepare('INSERT INTO products (name,description,category,price,sizes) VALUES (?,?,?,?,?)');
  [
    ['Маргарита', 'Томатный соус, моцарелла, базилик', 'pizza', 59000, sz(59000, 79000, 99000)],
    ['Пепперони', 'Пикантная пепперони, моцарелла, томатный соус', 'pizza', 69000, sz(69000, 89000, 109000)],
    ['Четыре сыра', 'Моцарелла, дорблю, пармезан, чеддер', 'pizza', 75000, sz(75000, 95000, 115000)],
    ['Гавайская', 'Курица, ананас, моцарелла', 'pizza', 65000, sz(65000, 85000, 105000)],
    ['Мясная', 'Говядина, колбаски, бекон, лук, моцарелла', 'pizza', 79000, sz(79000, 99000, 125000)],
    ['Грибная', 'Шампиньоны, сливочный соус, моцарелла', 'pizza', 62000, sz(62000, 82000, 102000)],
    ['BBQ с курицей', 'Курица, соус барбекю, красный лук, моцарелла', 'pizza', 68000, sz(68000, 88000, 108000)],
    ['Картофель фри', 'Хрустящий картофель с соусом на выбор', 'snacks', 18000, null],
    ['Куриные наггетсы', '9 штук с соусом', 'snacks', 28000, null],
    ['Кока-кола 0.5 л', '', 'drinks', 10000, null],
    ['Домашний лимонад 0.5 л', 'Лимон, мята', 'drinks', 15000, null],
    ['Чизкейк', 'Нежный классический чизкейк', 'desserts', 25000, null],
  ].forEach(r => ins.run(...r));
  const ia = db.prepare('INSERT INTO addons (name,price) VALUES (?,?)');
  [['Дополнительный сыр', 8000], ['Пепперони', 10000], ['Шампиньоны', 6000], ['Бекон', 10000], ['Халапеньо', 5000]].forEach(r => ia.run(...r));
  db.prepare('INSERT INTO promos (code,percent) VALUES (?,?)').run('PIZZA10', 10);
}

// ───────────────────────── Вспомогательное ─────────────────────────
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = msg => new HttpError(400, msg);
const md5 = s => crypto.createHash('md5').update(s).digest('hex');
const safeEq = (a, b) => { const A = Buffer.from(String(a)), B = Buffer.from(String(b)); return A.length === B.length && crypto.timingSafeEqual(A, B); };
const str = (v, min, max, what) => {
  const s = String(v ?? '').trim();
  if (s.length < min || s.length > max) throw bad(`Некорректное поле: ${what}`);
  return s;
};
const num = (v, min, max, what) => {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw bad(`Некорректное число: ${what}`);
  return n;
};

// простой ограничитель частоты запросов (в памяти)
const hits = new Map();
function limit(name, max, windowMs) {
  return (req, res, next) => {
    const key = name + ':' + req.ip, now = Date.now();
    const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) return res.status(429).json({ error: 'Слишком много запросов, попробуйте позже' });
    arr.push(now); hits.set(key, arr); next();
  };
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 3600e3)) hits.delete(k); }, 600e3).unref();

async function notify(order) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  try {
    const items = JSON.parse(order.items).map(i =>
      `• ${i.name}${i.size ? ' ' + i.size : ''}${i.addons.length ? ' (+' + i.addons.join(', ') + ')' : ''} × ${i.qty}`).join('\n');
    const pay = order.pay_method === 'cash' ? 'при получении' : `онлайн (${order.pay_method}) — ОПЛАЧЕНО`;
    const text = `🍕 Новый заказ №${order.id}\n${items}\n\nИтого: ${order.total.toLocaleString('ru-RU')} сум\nОплата: ${pay}\n` +
      `${order.delivery_type === 'delivery' ? 'Доставка: ' + order.address : 'Самовывоз'}\n` +
      `Клиент: ${order.customer_name}, ${order.phone}${order.comment ? '\nКомментарий: ' + order.comment : ''}`;
    const r = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text }),
    });
    if (!r.ok) console.error('Telegram:', r.status, await r.text());
  } catch (e) { console.error('Telegram error:', e.message); }
}

function markPaid(orderId) {
  const r = db.prepare("UPDATE orders SET payment_status='paid', status='new' WHERE id=? AND payment_status='unpaid'").run(orderId);
  if (r.changes) notify(db.prepare('SELECT * FROM orders WHERE id=?').get(orderId));
  return r.changes > 0;
}

// Сумма заказа ВСЕГДА считается на сервере по ценам из базы — данным браузера о цене доверять нельзя
function computeOrder(items, promoCode, deliveryType) {
  if (!Array.isArray(items) || !items.length || items.length > 50) throw bad('Корзина пуста');
  let subtotal = 0; const lines = [];
  const getP = db.prepare('SELECT * FROM products WHERE id=? AND available=1');
  const getA = db.prepare('SELECT * FROM addons WHERE id=? AND available=1');
  for (const it of items) {
    const p = getP.get(Number(it.productId));
    if (!p) throw bad('Одна из позиций больше недоступна. Обновите страницу');
    const qty = Math.min(Math.max(parseInt(it.qty) || 1, 1), 20);
    let price = p.price, sizeName = null;
    const sizes = p.sizes ? JSON.parse(p.sizes) : null;
    if (sizes && sizes.length) { const s = sizes.find(x => x.name === it.size) || sizes[0]; price = s.price; sizeName = s.name; }
    const addons = [];
    if (p.category === 'pizza' && Array.isArray(it.addons)) {
      for (const id of new Set(it.addons.map(Number))) { const a = getA.get(id); if (a) { price += a.price; addons.push(a.name); } }
    }
    lines.push({ productId: p.id, name: p.name, size: sizeName, addons, qty, unit: price });
    subtotal += price * qty;
  }
  let discount = 0, promo = null;
  if (promoCode && String(promoCode).trim()) {
    const pr = db.prepare('SELECT * FROM promos WHERE code=? AND active=1').get(String(promoCode).trim().toUpperCase());
    if (!pr) throw bad('Промокод не найден или не действует');
    discount = Math.round(subtotal * pr.percent / 100); promo = pr.code;
  }
  const fee = deliveryType === 'delivery' && !(FREE_FROM && subtotal - discount >= FREE_FROM) ? DELIVERY_FEE : 0;
  return { lines, subtotal, discount, promo, fee, total: subtotal - discount + fee };
}

function paymeUrl(o) {
  const p = `m=${PAYME.merchant};ac.order_id=${o.id};a=${o.total * 100};c=${SITE_URL}/?order=${o.id}&t=${o.token}`;
  return (PAYME.test ? 'https://test.paycom.uz/' : 'https://checkout.paycom.uz/') + Buffer.from(p).toString('base64');
}
function clickUrl(o) {
  return 'https://my.click.uz/services/pay?' + new URLSearchParams({
    service_id: CLICK.service, merchant_id: CLICK.merchant, amount: String(o.total),
    transaction_param: String(o.id), return_url: `${SITE_URL}/?order=${o.id}&t=${o.token}`,
  });
}
function payUrl(o) {
  if (o.payment_status !== 'unpaid') return null;
  if (o.pay_method === 'payme') return paymeUrl(o);
  if (o.pay_method === 'click') return clickUrl(o);
  if (o.pay_method === 'demo') return 'demo';
  return null;
}
const publicOrder = o => ({
  id: o.id, status: o.status, payment_status: o.payment_status, pay_method: o.pay_method, total: o.total,
  items: JSON.parse(o.items), delivery_type: o.delivery_type, payUrl: payUrl(o),
});

// ───────────────────────── Приложение ─────────────────────────
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'same-origin' });
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
const wrap = fn => (req, res, next) => {
  try { const r = fn(req, res, next); if (r && r.catch) r.catch(next); } catch (e) { next(e); }
};

// ── Публичное API ──
app.get('/api/config', (req, res) => {
  const methods = ['cash'];
  if (paymeOn) methods.push('payme');
  if (clickOn) methods.push('click');
  if (DEMO) methods.push('demo');
  res.json({ shopName: SHOP_NAME, methods, deliveryFee: DELIVERY_FEE, freeFrom: FREE_FROM });
});

app.get('/api/menu', wrap((req, res) => {
  const products = db.prepare('SELECT * FROM products WHERE available=1 ORDER BY id').all()
    .map(p => ({ ...p, sizes: p.sizes ? JSON.parse(p.sizes) : null }));
  res.json({ products, addons: db.prepare('SELECT id,name,price FROM addons WHERE available=1 ORDER BY id').all() });
}));

app.post('/api/quote', limit('quote', 60, 60e3), wrap((req, res) => {
  const c = computeOrder(req.body.items, req.body.promo, req.body.deliveryType === 'pickup' ? 'pickup' : 'delivery');
  res.json({ subtotal: c.subtotal, discount: c.discount, fee: c.fee, total: c.total, promo: c.promo });
}));

app.post('/api/orders', limit('order', 10, 600e3), wrap((req, res) => {
  const b = req.body || {};
  const deliveryType = b.deliveryType === 'pickup' ? 'pickup' : 'delivery';
  const name = str(b.name, 2, 60, 'имя');
  const phone = String(b.phone || '').replace(/[^\d+]/g, '');
  if (!/^\+?\d{9,15}$/.test(phone)) throw bad('Введите корректный номер телефона');
  const address = deliveryType === 'delivery' ? str(b.address, 5, 200, 'адрес') : '';
  const comment = String(b.comment || '').trim().slice(0, 300);
  const allowed = ['cash', ...(paymeOn ? ['payme'] : []), ...(clickOn ? ['click'] : []), ...(DEMO ? ['demo'] : [])];
  if (!allowed.includes(b.payMethod)) throw bad('Выберите способ оплаты');
  const c = computeOrder(b.items, b.promo, deliveryType);
  if (c.total <= 0) throw bad('Некорректная сумма заказа');
  const cash = b.payMethod === 'cash';
  const token = crypto.randomBytes(16).toString('hex');
  const info = db.prepare(`INSERT INTO orders (token,customer_name,phone,address,comment,delivery_type,items,subtotal,discount,
    delivery_fee,total,promo,pay_method,payment_status,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(token, name, phone, address, comment, deliveryType, JSON.stringify(c.lines), c.subtotal, c.discount, c.fee,
      c.total, c.promo, b.payMethod, cash ? 'cash' : 'unpaid', cash ? 'new' : 'awaiting_payment');
  const order = db.prepare('SELECT * FROM orders WHERE id=?').get(info.lastInsertRowid);
  if (cash) notify(order);
  res.json({ id: order.id, token, payUrl: payUrl(order) });
}));

app.get('/api/orders/:id', wrap((req, res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(Number(req.params.id));
  if (!o || !safeEq(o.token, req.query.token || '')) throw new HttpError(404, 'Заказ не найден');
  res.json(publicOrder(o));
}));

// Демо-оплата (без денег). Работает только при DEMO_PAYMENTS=true
app.post('/api/demo/pay/:id', wrap((req, res) => {
  if (!DEMO) throw new HttpError(404, 'Не найдено');
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(Number(req.params.id));
  if (!o || !safeEq(o.token, req.body.token || '') || o.pay_method !== 'demo') throw new HttpError(404, 'Заказ не найден');
  markPaid(o.id);
  res.json({ ok: true });
}));

// ── Админка ──
const loginLimit = limit('login', 8, 15 * 60e3);
app.post('/api/admin/login', loginLimit, wrap(async (req, res) => {
  const hash = env.ADMIN_PASSWORD_HASH;
  if (!hash) throw new HttpError(503, 'Вход в админку не настроен (ADMIN_PASSWORD_HASH)');
  const { username, password } = req.body || {};
  const okUser = safeEq(String(username || ''), env.ADMIN_USER || 'admin');
  const okPass = await bcrypt.compare(String(password || ''), hash);
  if (!okUser || !okPass) throw new HttpError(401, 'Неверный логин или пароль');
  res.json({ token: jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '8h' }) });
}));

const auth = (req, res, next) => {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');
  try { jwt.verify(t, JWT_SECRET); next(); } catch { res.status(401).json({ error: 'Требуется вход' }); }
};
const admin = express.Router();
admin.use(auth);
app.use('/api/admin', admin); // маршрут /login объявлен выше и обрабатывается раньше

const STATUSES = ['new', 'cooking', 'delivering', 'done', 'cancelled'];
admin.get('/orders', wrap((req, res) => {
  const rows = db.prepare("SELECT * FROM orders WHERE status!='awaiting_payment' ORDER BY id DESC LIMIT 200").all()
    .map(o => ({ ...o, items: JSON.parse(o.items), token: undefined }));
  res.json(rows);
}));
admin.patch('/orders/:id', wrap((req, res) => {
  const st = req.body.status;
  if (!STATUSES.includes(st)) throw bad('Неверный статус');
  db.prepare('UPDATE orders SET status=? WHERE id=?').run(st, Number(req.params.id));
  res.json({ ok: true });
}));

function crud(route, table, spec) {
  const cols = Object.keys(spec);
  const clean = body => Object.fromEntries(cols.map(c => [c, spec[c](body?.[c])]));
  admin.get(route, wrap((req, res) => res.json(db.prepare(`SELECT * FROM ${table} ORDER BY id`).all())));
  admin.post(route, wrap((req, res) => {
    const info = db.prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${cols.map(c => '@' + c).join(',')})`).run(clean(req.body));
    res.json({ id: info.lastInsertRowid });
  }));
  admin.put(route + '/:id', wrap((req, res) => {
    db.prepare(`UPDATE ${table} SET ${cols.map(c => c + '=@' + c).join(',')} WHERE id=@id`).run({ ...clean(req.body), id: Number(req.params.id) });
    res.json({ ok: true });
  }));
  admin.delete(route + '/:id', wrap((req, res) => {
    db.prepare(`DELETE FROM ${table} WHERE id=?`).run(Number(req.params.id));
    res.json({ ok: true });
  }));
}
const flag = v => (v ? 1 : 0);
const sizesClean = v => {
  if (v === null || v === undefined || v === '') return null;
  const arr = typeof v === 'string' ? JSON.parse(v) : v;
  if (!Array.isArray(arr)) throw bad('Размеры заданы неверно');
  if (!arr.length) return null;
  return JSON.stringify(arr.map(s => ({ name: str(s.name, 1, 30, 'размер'), price: num(s.price, 1, 1e8, 'цена размера') })));
};
crud('/products', 'products', {
  name: v => str(v, 1, 80, 'название'), description: v => String(v || '').slice(0, 300),
  category: v => { if (!['pizza', 'snacks', 'drinks', 'desserts'].includes(v)) throw bad('Категория'); return v; },
  price: v => num(v, 1, 1e8, 'цена'), sizes: sizesClean,
  image: v => { const s = String(v || '').trim(); if (s && !/^https:\/\//.test(s)) throw bad('Ссылка на картинку должна начинаться с https://'); return s.slice(0, 500); },
  available: flag,
});
crud('/addons', 'addons', { name: v => str(v, 1, 60, 'название'), price: v => num(v, 0, 1e8, 'цена'), available: flag });
crud('/promos', 'promos', { code: v => str(v, 2, 30, 'код').toUpperCase(), percent: v => num(v, 1, 90, 'процент'), active: flag });

// ── Payme (Merchant API, JSON-RPC). Адрес для кабинета Payme: https://ВАШ-САЙТ/api/payme ──
const TX_TIMEOUT = 12 * 3600 * 1000;
const perr = (code, ru, data) => Object.assign(new Error(ru), { rpc: { code, message: { ru, uz: ru, en: ru }, data: data || null } });

app.post('/api/payme', (req, res) => {
  const id = req.body?.id ?? null;
  const reply = (result) => res.json({ result, id });
  const fail = e => res.json({ error: e.rpc || { code: -32400, message: { ru: 'Системная ошибка', uz: 'Tizim xatosi', en: 'System error' } }, id });
  try {
    if (!paymeOn) throw perr(-32400, 'Payme не настроен');
    const expected = 'Basic ' + Buffer.from('Paycom:' + PAYME.key).toString('base64');
    if (!safeEq(req.headers.authorization || '', expected)) throw perr(-32504, 'Недостаточно привилегий');
    const { method, params = {} } = req.body || {};
    const getTx = txid => db.prepare('SELECT * FROM payme_tx WHERE id=?').get(String(txid));
    const expire = tx => { db.prepare('UPDATE payme_tx SET state=-1, cancel_time=?, reason=4 WHERE id=?').run(Date.now(), tx.id); };

    const checkOrder = () => {
      const oid = parseInt(params.account && params.account.order_id);
      const o = oid ? db.prepare('SELECT * FROM orders WHERE id=?').get(oid) : null;
      if (!o) throw perr(-31050, 'Заказ не найден', 'order_id');
      if (o.pay_method !== 'payme' || o.payment_status !== 'unpaid' || o.status === 'cancelled') throw perr(-31051, 'Заказ не ожидает оплаты', 'order_id');
      if (params.amount !== o.total * 100) throw perr(-31001, 'Неверная сумма');
      return o;
    };
    const fmt = tx => ({ create_time: tx.create_time, perform_time: tx.perform_time, cancel_time: tx.cancel_time, transaction: String(tx.id), state: tx.state, reason: tx.reason ?? null });

    switch (method) {
      case 'CheckPerformTransaction':
        checkOrder(); return reply({ allow: true });
      case 'CreateTransaction': {
        const tx = getTx(params.id);
        if (tx) {
          if (tx.state !== 1) throw perr(-31008, 'Невозможно выполнить операцию');
          if (Date.now() - tx.time > TX_TIMEOUT) { expire(tx); throw perr(-31008, 'Время транзакции истекло'); }
          return reply({ create_time: tx.create_time, transaction: String(tx.id), state: 1 });
        }
        const o = checkOrder();
        if (db.prepare('SELECT 1 FROM payme_tx WHERE order_id=? AND state=1').get(o.id)) throw perr(-31099, 'Для заказа уже есть транзакция', 'order_id');
        const now = Date.now();
        db.prepare('INSERT INTO payme_tx (id,order_id,amount,state,time,create_time) VALUES (?,?,?,1,?,?)').run(String(params.id), o.id, params.amount, params.time, now);
        return reply({ create_time: now, transaction: String(params.id), state: 1 });
      }
      case 'PerformTransaction': {
        const tx = getTx(params.id);
        if (!tx) throw perr(-31003, 'Транзакция не найдена');
        if (tx.state === 2) return reply({ transaction: String(tx.id), perform_time: tx.perform_time, state: 2 });
        if (tx.state !== 1) throw perr(-31008, 'Невозможно выполнить операцию');
        if (Date.now() - tx.time > TX_TIMEOUT) { expire(tx); throw perr(-31008, 'Время транзакции истекло'); }
        const now = Date.now();
        db.transaction(() => { db.prepare('UPDATE payme_tx SET state=2, perform_time=? WHERE id=?').run(now, tx.id); markPaid(tx.order_id); })();
        return reply({ transaction: String(tx.id), perform_time: now, state: 2 });
      }
      case 'CancelTransaction': {
        const tx = getTx(params.id);
        if (!tx) throw perr(-31003, 'Транзакция не найдена');
        if (tx.state === 1) {
          const now = Date.now();
          db.prepare('UPDATE payme_tx SET state=-1, cancel_time=?, reason=? WHERE id=?').run(now, params.reason ?? null, tx.id);
          return reply({ transaction: String(tx.id), cancel_time: now, state: -1 });
        }
        if (tx.state === 2) {
          const o = db.prepare('SELECT * FROM orders WHERE id=?').get(tx.order_id);
          if (o && ['delivering', 'done'].includes(o.status)) throw perr(-31007, 'Заказ выполнен. Невозможно отменить транзакцию');
          const now = Date.now();
          db.transaction(() => {
            db.prepare('UPDATE payme_tx SET state=-2, cancel_time=?, reason=? WHERE id=?').run(now, params.reason ?? null, tx.id);
            db.prepare("UPDATE orders SET payment_status='refunded', status='cancelled' WHERE id=?").run(tx.order_id);
          })();
          return reply({ transaction: String(tx.id), cancel_time: now, state: -2 });
        }
        return reply({ transaction: String(tx.id), cancel_time: tx.cancel_time, state: tx.state });
      }
      case 'CheckTransaction': {
        const tx = getTx(params.id);
        if (!tx) throw perr(-31003, 'Транзакция не найдена');
        return reply(fmt(tx));
      }
      case 'GetStatement': {
        const rows = db.prepare('SELECT * FROM payme_tx WHERE time>=? AND time<=? ORDER BY time').all(Number(params.from), Number(params.to));
        return reply({ transactions: rows.map(tx => ({ id: tx.id, time: tx.time, amount: tx.amount, account: { order_id: String(tx.order_id) }, ...fmt(tx) })) });
      }
      default:
        throw perr(-32601, 'Метод не найден');
    }
  } catch (e) {
    if (!e.rpc) console.error('Payme error:', e);
    fail(e);
  }
});

// ── Click (Shop API). Адреса для кабинета Click: /api/click/prepare и /api/click/complete ──
function clickCheckSign(b, withPrepare) {
  const s = [b.click_trans_id, b.service_id, CLICK.secret, b.merchant_trans_id, withPrepare ? b.merchant_prepare_id : '', b.amount, b.action, b.sign_time].join('');
  return safeEq(md5(s), String(b.sign_string || ''));
}
function clickHandler(isComplete) {
  return (req, res) => {
    const b = req.body || {};
    const base = { click_trans_id: b.click_trans_id, merchant_trans_id: b.merchant_trans_id };
    const out = (error, note, extra) => res.json({ ...base, ...extra, error, error_note: note });
    try {
      if (!clickOn) return out(-8, 'Error in request from click');
      if (String(b.service_id) !== String(CLICK.service) || !clickCheckSign(b, isComplete)) return out(-1, 'SIGN CHECK FAILED!');
      if (Number(b.action) !== (isComplete ? 1 : 0)) return out(-3, 'Action not found');
      const order = db.prepare('SELECT * FROM orders WHERE id=?').get(Number(b.merchant_trans_id));
      if (!order || order.pay_method !== 'click') return out(-5, 'User does not exist');
      if (Math.abs(Number(b.amount) - order.total) > 0.01) return out(-2, 'Incorrect parameter amount');

      if (!isComplete) {
        if (order.payment_status === 'paid') return out(-4, 'Already paid');
        if (order.status === 'cancelled') return out(-9, 'Transaction cancelled');
        let tx = db.prepare('SELECT * FROM click_tx WHERE click_trans_id=?').get(String(b.click_trans_id));
        if (!tx) {
          const info = db.prepare('INSERT INTO click_tx (click_trans_id,order_id,amount,state) VALUES (?,?,?,0)').run(String(b.click_trans_id), order.id, Number(b.amount));
          tx = { id: info.lastInsertRowid };
        }
        return out(0, 'Success', { merchant_prepare_id: tx.id });
      }
      const tx = db.prepare('SELECT * FROM click_tx WHERE id=?').get(Number(b.merchant_prepare_id));
      if (!tx || tx.order_id !== order.id) return out(-6, 'Transaction does not exist');
      if (tx.state === 1 || order.payment_status === 'paid') return out(-4, 'Already paid', { merchant_confirm_id: tx.id });
      if (tx.state === -1 || order.status === 'cancelled') return out(-9, 'Transaction cancelled');
      if (Number(b.error) < 0) {
        db.prepare('UPDATE click_tx SET state=-1 WHERE id=?').run(tx.id);
        return out(-9, 'Transaction cancelled', { merchant_confirm_id: tx.id });
      }
      db.transaction(() => { db.prepare('UPDATE click_tx SET state=1 WHERE id=?').run(tx.id); markPaid(order.id); })();
      return out(0, 'Success', { merchant_confirm_id: tx.id });
    } catch (e) {
      console.error('Click error:', e);
      return out(-7, 'Failed to update user');
    }
  };
}
app.post('/api/click/prepare', clickHandler(false));
app.post('/api/click/complete', clickHandler(true));

// ── Ошибки ──
app.use('/api', (req, res) => res.status(404).json({ error: 'Не найдено' }));
app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Некорректный запрос' });
  console.error(err);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

module.exports = app;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Сайт «${SHOP_NAME}» запущен: ${SITE_URL}  (админка: ${SITE_URL}/admin.html)`));
}
