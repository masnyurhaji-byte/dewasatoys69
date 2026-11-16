import { getStore } from '@netlify/blobs';
import { createHmac, timingSafeEqual } from 'node:crypto';

const COOKIE = 'dt_admin_session';
const MAX_AGE = 60 * 60 * 8;
const DEFAULT_DATA = {
  waNumber: '6282164965465',
  storeName: 'DewasaToys',
  announcement: 'Layanan pelanggan privat · Pemesanan mudah melalui WhatsApp',
  heroTitle: 'Pilihan Produk Dewasa dalam Satu Tempat',
  heroDescription: 'Jelajahi katalog produk pria dan wanita dengan pengalaman belanja yang praktis, informatif, dan mengutamakan privasi. Konsultasi serta pemesanan tersedia melalui WhatsApp.',
  products: [
    { id: 'p1', name: 'Produk Pria 01', category: 'Pria', price: 'Tanyakan harga', description: 'Tanyakan detail, pilihan, dan ketersediaan produk kepada admin.', image: '' },
    { id: 'p2', name: 'Produk Pria 02', category: 'Pria', price: 'Tanyakan harga', description: 'Tanyakan detail, pilihan, dan ketersediaan produk kepada admin.', image: '' },
    { id: 'p3', name: 'Produk Wanita 01', category: 'Wanita', price: 'Tanyakan harga', description: 'Tanyakan detail, pilihan, dan ketersediaan produk kepada admin.', image: '' },
    { id: 'p4', name: 'Produk Wanita 02', category: 'Wanita', price: 'Tanyakan harga', description: 'Tanyakan detail, pilihan, dan ketersediaan produk kepada admin.', image: '' },
    { id: 'p5', name: 'Produk Pasangan 01', category: 'Pasangan', price: 'Tanyakan harga', description: 'Tanyakan detail, pilihan, dan ketersediaan produk kepada admin.', image: '' },
    { id: 'p6', name: 'Aksesori 01', category: 'Aksesori', price: 'Tanyakan harga', description: 'Tanyakan detail, pilihan, dan ketersediaan produk kepada admin.', image: '' }
  ]
};

const headers = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
function response(statusCode, body, extra = {}) { return { statusCode, headers: { ...headers, ...extra }, body: JSON.stringify(body) }; }
function secret() { return process.env.SESSION_SECRET || process.env.ADMIN_PASSWORD || ''; }
function sign(value) { return createHmac('sha256', secret()).update(value).digest('hex'); }
function cookieValue(event) {
  const raw = event.headers.cookie || event.headers.Cookie || '';
  const item = raw.split(';').map(v => v.trim()).find(v => v.startsWith(COOKIE + '='));
  return item ? decodeURIComponent(item.slice(COOKIE.length + 1)) : '';
}
function isAuthorized(event) {
  if (!secret()) return false;
  const token = cookieValue(event);
  const [expires, mac] = token.split('.');
  if (!expires || !mac || Number(expires) < Math.floor(Date.now() / 1000)) return false;
  const expected = sign(expires);
  try { return timingSafeEqual(Buffer.from(mac), Buffer.from(expected)); } catch { return false; }
}
function sessionCookie() {
  const expires = String(Math.floor(Date.now() / 1000) + MAX_AGE);
  return `${COOKIE}=${encodeURIComponent(expires + '.' + sign(expires))}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${MAX_AGE}`;
}
const store = () => getStore({ name: 'dewasatoys-content', consistency: 'strong' });
async function readData() { return (await store().get('store.json', { type: 'json' })) || DEFAULT_DATA; }

export default async (event) => {
  const method = event.httpMethod;
  if (method === 'GET') {
    const data = await readData();
    return response(200, { ok: true, data });
  }
  if (method !== 'POST') return response(405, { ok: false, error: 'Method not allowed' });
  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { return response(400, { ok: false, error: 'Format data tidak valid.' }); }

  if (body.action === 'login') {
    const password = process.env.ADMIN_PASSWORD;
    if (!password || !secret()) return response(503, { ok: false, error: 'ADMIN_PASSWORD dan SESSION_SECRET belum diatur di Netlify.' });
    const supplied = String(body.password || '');
    const a = Buffer.from(supplied); const b = Buffer.from(password);
    let valid = false;
    try { valid = a.length === b.length && timingSafeEqual(a, b); } catch { valid = false; }
    if (!valid) return response(401, { ok: false, error: 'Password tidak sesuai.' });
    return response(200, { ok: true }, { 'set-cookie': sessionCookie() });
  }
  if (body.action === 'session') return isAuthorized(event) ? response(200, { ok: true }) : response(401, { ok: false });
  if (body.action === 'logout') return response(200, { ok: true }, { 'set-cookie': `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0` });
  if (body.action === 'save') {
    if (!isAuthorized(event)) return response(401, { ok: false, error: 'Sesi admin berakhir. Silakan login kembali.' });
    const data = body.data;
    if (!data || !Array.isArray(data.products) || typeof data.waNumber !== 'string') return response(400, { ok: false, error: 'Data toko tidak lengkap.' });
    if (data.products.length > 500) return response(400, { ok: false, error: 'Maksimal 500 produk.' });
    await store().setJSON('store.json', data);
    return response(200, { ok: true, message: 'Perubahan berhasil disimpan.' });
  }
  return response(400, { ok: false, error: 'Aksi tidak dikenal.' });
};
