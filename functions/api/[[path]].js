// Cloudflare Pages Function  →  /api/*
// 회원가입 · 로그인 · 계정별 데이터 저장 (D1 바인딩 이름: DB)

const STORES = { suppliers: 'id', products: 'id', orders: 'id', rules: 'key', meta: 'key' };
const ITER = 30000;                 // 비밀번호 해시 반복 횟수 (계정별로 저장되므로 나중에 바꿔도 기존 계정 유지)
const SESSION_SEC = 14 * 86400;     // 로그인 유지 기간 14일
const MAX_BODY = 3000000;
const PAGE = 500;
const enc = new TextEncoder();

const J = (o, status = 200, headers) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...(headers || {}) },
  });
const fail = (msg, status = 400) => { throw J({ error: msg }, status); };

const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
async function pbkdf2(pw, salt, iter) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, k, 256));
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function getCookie(req, name) {
  for (const p of (req.headers.get('cookie') || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0 && p.slice(0, i).trim() === name) return p.slice(i + 1).trim();
  }
  return '';
}
const setSid = (v, age) => ({ 'set-cookie': `sid=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}` });

async function readJson(req) {
  const t = await req.text();
  if (t.length > MAX_BODY) fail('요청이 너무 큽니다.', 413);
  try { return JSON.parse(t); } catch (e) { return fail('잘못된 요청입니다.'); }
}

async function newSession(env, username) {
  const raw = hex(crypto.getRandomValues(new Uint8Array(32)));
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires<?').bind(now),
    env.DB.prepare('INSERT INTO sessions(token,username,expires) VALUES(?,?,?)').bind(await sha256(raw), username, now + SESSION_SEC * 1000),
  ]);
  return raw;
}

async function currentUser(env, req) {
  const sid = getCookie(req, 'sid');
  if (!sid) return null;
  const row = await env.DB.prepare('SELECT username,expires FROM sessions WHERE token=?').bind(await sha256(sid)).first();
  return row && row.expires > Date.now() ? row.username : null;
}

function readCred(b) {
  const username = String((b && b.username) || '').trim().toLowerCase();
  const password = String((b && b.password) || '');
  return { username, password };
}

async function signup(env, req) {
  const { username, password } = readCred(await readJson(req));
  if (!/^[a-z0-9_]{4,20}$/.test(username)) fail('아이디는 영문 소문자·숫자·밑줄(_) 4~20자로 입력해 주세요.');
  if (password.length < 6 || password.length > 100) fail('비밀번호는 6자 이상으로 입력해 주세요.');
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  const now = Date.now();
  const c = await env.DB.prepare('SELECT COUNT(*) n FROM signup_log WHERE ip=? AND ts>?').bind(ip, now - 3600000).first();
  if (c && c.n >= 10) fail('가입 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요.', 429);
  if (await env.DB.prepare('SELECT 1 x FROM users WHERE username=?').bind(username).first()) fail('이미 사용 중인 아이디입니다.', 409);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, ITER);
  try {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO users(username,salt,hash,iter,created_at) VALUES(?,?,?,?,?)').bind(username, hex(salt), hash, ITER, now),
      env.DB.prepare('INSERT INTO signup_log(ip,ts) VALUES(?,?)').bind(ip, now),
      env.DB.prepare('DELETE FROM signup_log WHERE ts<?').bind(now - 86400000),
    ]);
  } catch (e) {
    fail('이미 사용 중인 아이디입니다.', 409);
  }
  const sid = await newSession(env, username);
  return J({ ok: true, username }, 200, setSid(sid, SESSION_SEC));
}

async function login(env, req) {
  const { username, password } = readCred(await readJson(req));
  const bad = () => J({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' }, 401);
  if (!username || !password) return bad();
  const row = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
  if (!row) return bad();
  const now = Date.now();
  if (row.locked_until > now) {
    const m = Math.ceil((row.locked_until - now) / 60000);
    return J({ error: `로그인 시도가 너무 많습니다. ${m}분 뒤에 다시 시도해 주세요.` }, 429);
  }
  const h = await pbkdf2(password, unhex(row.salt), row.iter);
  if (!same(h, row.hash)) {
    const f = row.fails + 1;
    if (f >= 5) await env.DB.prepare('UPDATE users SET fails=0, locked_until=? WHERE username=?').bind(now + 600000, username).run();
    else await env.DB.prepare('UPDATE users SET fails=? WHERE username=?').bind(f, username).run();
    return bad();
  }
  if (row.fails) await env.DB.prepare('UPDATE users SET fails=0 WHERE username=?').bind(username).run();
  const sid = await newSession(env, username);
  return J({ ok: true, username }, 200, setSid(sid, SESSION_SEC));
}

async function logout(env, req) {
  const sid = getCookie(req, 'sid');
  if (sid) await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(await sha256(sid)).run();
  return J({ ok: true }, 200, setSid('', 0));
}

async function readData(env, user, url) {
  const store = url.searchParams.get('store');
  if (!Object.hasOwn(STORES, store)) fail('잘못된 요청입니다.');
  const after = parseInt(url.searchParams.get('after'), 10) || 0;
  const { results } = await env.DB
    .prepare('SELECT rowid AS r, d FROM records WHERE u=? AND s=? AND rowid>? ORDER BY rowid LIMIT ?')
    .bind(user, store, after, PAGE)
    .all();
  const last = results.length ? results[results.length - 1].r : after;
  const body = '{"rows":[' + results.map((x) => x.d).join(',') + '],"last":' + last + ',"done":' + (results.length < PAGE) + '}';
  return new Response(body, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
}

async function writeData(env, user, body) {
  const ops = Array.isArray(body && body.ops) ? body.ops : [];
  if (ops.length > 100) fail('요청이 너무 큽니다.', 413);
  const st = [];
  const put = {};
  for (const [s, k] of Object.entries(STORES)) {
    put[s] = env.DB.prepare(
      `INSERT INTO records(u,s,k,d) SELECT ?, ?, CAST(json_extract(value,'$.${k}') AS TEXT), value FROM json_each(?) WHERE true ON CONFLICT(u,s,k) DO UPDATE SET d=excluded.d`
    );
  }
  const del = env.DB.prepare('DELETE FROM records WHERE u=? AND s=? AND k IN (SELECT CAST(value AS TEXT) FROM json_each(?))');
  const clr = env.DB.prepare('DELETE FROM records WHERE u=? AND s=?');

  for (const op of ops) {
    if (!op || !Object.hasOwn(STORES, op.store)) continue;
    const kf = STORES[op.store];
    if (op.op === 'put' && Array.isArray(op.rows)) {
      let chunk = [], size = 0;
      const flush = () => {
        if (chunk.length) st.push(put[op.store].bind(user, op.store, JSON.stringify(chunk)));
        chunk = []; size = 0;
      };
      for (const r of op.rows) {
        if (!r || typeof r !== 'object' || r[kf] === undefined || r[kf] === null || r[kf] === '') continue;
        const n = JSON.stringify(r).length;
        if (n > 1500000) continue;
        if (size + n > 80000) flush();
        chunk.push(r); size += n + 1;
      }
      flush();
    } else if (op.op === 'del' && Array.isArray(op.keys)) {
      for (let i = 0; i < op.keys.length; i += 2000) st.push(del.bind(user, op.store, JSON.stringify(op.keys.slice(i, i + 2000))));
    } else if (op.op === 'clear') {
      st.push(clr.bind(user, op.store));
    }
  }
  if (st.length) await env.DB.batch(st);
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
  const method = request.method;
  if (!env.DB) return J({ error: '서버 설정 오류입니다. D1 바인딩(DB)을 확인해 주세요.' }, 500);
  try {
    if (method === 'POST') {
      const o = request.headers.get('origin');
      if (o) {
        let h = '';
        try { h = new URL(o).host; } catch (e) {}
        if (h !== url.host) return J({ error: '허용되지 않은 요청입니다.' }, 403);
      }
    }
    if (route === 'signup' && method === 'POST') return await signup(env, request);
    if (route === 'login' && method === 'POST') return await login(env, request);
    if (route === 'logout' && method === 'POST') return await logout(env, request);

    const user = await currentUser(env, request);
    if (!user) return J({ error: '로그인이 필요합니다.' }, 401);

    if (route === 'me' && method === 'GET') return J({ username: user });
    if (route === 'data' && method === 'GET') return await readData(env, user, url);
    if (route === 'sync' && method === 'POST') {
      await writeData(env, user, await readJson(request));
      return J({ ok: true });
    }
    return J({ error: 'Not found' }, 404);
  } catch (e) {
    if (e instanceof Response) return e;
    console.error(e);
    return J({ error: '서버 오류가 발생했습니다.' }, 500);
  }
}
