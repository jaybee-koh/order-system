// Cloudflare Pages Function  →  /api/mall/*
// 쇼핑몰 계정관리(암호화 저장) · 주문 자동수집 요청 · RPA 도우미 프로그램 연동
// 기존 functions/api/[[path]].js 는 수정하지 않습니다. (더 구체적인 경로라서 이 파일이 먼저 처리합니다)
//
// 필요한 설정 (Cloudflare Pages > Settings > Variables and Secrets, 모두 "Secret"으로 저장)
//   CRED_KEY      쇼핑몰 비밀번호 암호화 키 (길고 무작위한 문자열, 한 번 정하면 바꾸지 마세요)
//   WORKER_TOKEN  도우미 프로그램 인증 토큰 (길고 무작위한 문자열)
//   WORKER_USER   도우미 프로그램이 처리할 발주관리 로그인 아이디 (예: myid)
// D1 바인딩 DB 는 기존 것을 그대로 사용하며, 새 테이블은 필요 없습니다. (records 테이블 재사용)

const enc = new TextEncoder();
const dec = new TextDecoder();

const MALL_STORE = 'mall';      // 쇼핑몰 설정(상태, 아이디)
const CRED_STORE = 'mallcred';  // 암호화된 비밀번호 (브라우저로는 절대 내려가지 않음)
const JOB_STORE = 'mjob';       // 수집 요청(작업)
const FILE_STORE = 'mfile';     // 도우미가 받아온 주문 파일
const META_STORE = 'mmeta';     // 도우미 접속 시각 등
const MAX_BODY = 3000000;
const MAX_FILE_B64 = 1800000;   // D1 행 크기 한도 때문에 파일은 약 1.3MB(엑셀 기준)까지
const MAX_DAYS = 93;
const STALE_MS = 15 * 60 * 1000;

// [id, 화면 표시명, 주문 데이터에 기록할 쇼핑몰명(기존 주문수집 목록과 맞춤)]
const DEFAULT_MALLS = [
  ['smartstore', '스마트스토어', '스마트스토어'],
  ['gmarket', 'ESM지마켓', 'ESM'],
  ['auction', 'ESM옥션', 'ESM'],
  ['11st', '11번가', '11번가'],
  ['coupang', '쿠팡', '쿠팡'],
  ['kakao', '카카오스토어', '카카오'],
  ['lotteon', '롯데온', '롯데온'],
  ['shoppingnt', '쇼핑엔티', '쇼핑엔티'],
  ['hyundaihmall', '현대홈쇼핑', '현대홈쇼핑'],
  ['cjonstyle', 'CJ오쇼핑', 'CJ오쇼핑'],
  ['gsshop', 'GS홈쇼핑', 'GS홈쇼핑'],
  ['nsmall', 'NS홈쇼핑', '농수산홈쇼핑'],
  ['ssg', 'SSG', '신세계'],
  ['hnsmall', '홈앤쇼핑', '홈앤쇼핑'],
  ['toss', '토스쇼핑', '토스쇼핑'],
];
const MALL_IDS = new Set(DEFAULT_MALLS.map((m) => m[0]));

const J = (o, status = 200) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
const fail = (msg, status = 400) => { throw J({ error: msg }, status); };

const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
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
function b64enc(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64dec(s) {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function readJson(req) {
  const t = await req.text();
  if (t.length > MAX_BODY) fail('요청이 너무 큽니다.', 413);
  try { return JSON.parse(t); } catch (e) { return fail('잘못된 요청입니다.'); }
}

async function currentUser(env, req) {
  const sid = getCookie(req, 'sid');
  if (!sid) return null;
  const row = await env.DB.prepare('SELECT username,expires FROM sessions WHERE token=?').bind(await sha256(sid)).first();
  return row && row.expires > Date.now() ? row.username : null;
}

/* ---------- 비밀번호 암호화 (AES-256-GCM) ---------- */
async function aesKey(env) {
  if (!env.CRED_KEY || String(env.CRED_KEY).length < 16) fail('서버 설정이 필요합니다. CRED_KEY(16자 이상)를 등록해 주세요.', 500);
  const raw = await crypto.subtle.digest('SHA-256', enc.encode(String(env.CRED_KEY)));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function encryptPw(env, user, mall, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(user + '|' + mall) },
    await aesKey(env),
    enc.encode(plain)
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return b64enc(out);
}
async function decryptPw(env, user, mall, blob) {
  const u8 = b64dec(blob);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: u8.subarray(0, 12), additionalData: enc.encode(user + '|' + mall) },
    await aesKey(env),
    u8.subarray(12)
  );
  return dec.decode(pt);
}

/* ---------- records 테이블 도우미 ---------- */
const getRec = async (env, u, s, k) => {
  const r = await env.DB.prepare('SELECT d FROM records WHERE u=? AND s=? AND k=?').bind(u, s, k).first();
  return r ? JSON.parse(r.d) : null;
};
const putRec = (env, u, s, k, o) =>
  env.DB.prepare('INSERT INTO records(u,s,k,d) VALUES(?,?,?,?) ON CONFLICT(u,s,k) DO UPDATE SET d=excluded.d').bind(u, s, k, JSON.stringify(o));
const delRec = (env, u, s, k) => env.DB.prepare('DELETE FROM records WHERE u=? AND s=? AND k=?').bind(u, s, k);

const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));

/* ================= 쇼핑몰 목록 / 저장 ================= */
async function listMalls(env, user) {
  const { results } = await env.DB.prepare('SELECT k, d FROM records WHERE u=? AND s=?').bind(user, MALL_STORE).all();
  const saved = {};
  for (const r of results) { try { saved[r.k] = JSON.parse(r.d); } catch (e) {} }
  const { results: cr } = await env.DB.prepare('SELECT k FROM records WHERE u=? AND s=?').bind(user, CRED_STORE).all();
  const hasPw = new Set(cr.map((x) => x.k));
  return DEFAULT_MALLS.map(([id, name, orderMall]) => {
    const s = saved[id] || {};
    return {
      id, name, orderMall,
      status: s.status === '거래정지' ? '거래정지' : '거래중',
      loginId: s.loginId || '',
      hasPw: hasPw.has(id),
      updatedAt: s.updatedAt || null,
    };
  });
}

async function saveMall(env, user, body) {
  const id = String((body && body.id) || '');
  if (!MALL_IDS.has(id)) fail('알 수 없는 쇼핑몰입니다.');
  const cur = (await getRec(env, user, MALL_STORE, id)) || {};
  const next = { ...cur };
  if (body.status !== undefined) {
    if (body.status !== '거래중' && body.status !== '거래정지') fail('거래 상태가 올바르지 않습니다.');
    next.status = body.status;
  }
  if (body.loginId !== undefined) {
    const lid = String(body.loginId).trim();
    if (lid.length > 100) fail('아이디가 너무 깁니다.');
    next.loginId = lid;
  }
  next.updatedAt = Date.now();
  const st = [putRec(env, user, MALL_STORE, id, next)];
  if (body.password !== undefined && String(body.password) !== '') {
    const pw = String(body.password);
    if (pw.length > 200) fail('비밀번호가 너무 깁니다.');
    st.push(putRec(env, user, CRED_STORE, id, { pw: await encryptPw(env, user, id, pw), at: Date.now() }));
  }
  if (body.clearPassword === true) st.push(delRec(env, user, CRED_STORE, id));
  await env.DB.batch(st);
  return J({ ok: true });
}

/* ================= 수집 요청 / 작업 조회 ================= */
async function requestCollect(env, user, body) {
  const from = body && body.from, to = body && body.to;
  if (!isDate(from) || !isDate(to)) fail('수집 기간을 올바르게 입력하세요.');
  if (from > to) fail('시작일이 종료일보다 늦습니다.');
  if ((Date.parse(to) - Date.parse(from)) / 86400000 > MAX_DAYS) fail('수집 기간은 최대 ' + MAX_DAYS + '일까지 가능합니다.');
  const ids = Array.isArray(body.malls) ? [...new Set(body.malls.map(String))].filter((x) => MALL_IDS.has(x)) : [];
  if (!ids.length) fail('수집할 쇼핑몰을 선택하세요.');

  const malls = await listMalls(env, user);
  const byId = new Map(malls.map((m) => [m.id, m]));
  const { results: open } = await env.DB
    .prepare("SELECT d FROM records WHERE u=? AND s=? AND json_extract(d,'$.status') IN ('pending','running')")
    .bind(user, JOB_STORE).all();
  const busy = new Set(open.map((r) => JSON.parse(r.d).mall));

  const st = [], created = [], skipped = [];
  const now = Date.now();
  for (const id of ids) {
    const m = byId.get(id);
    if (m.status !== '거래중') { skipped.push({ mall: m.name, why: '거래정지 상태' }); continue; }
    if (!m.loginId || !m.hasPw) { skipped.push({ mall: m.name, why: '아이디/비밀번호 미설정' }); continue; }
    if (busy.has(id)) { skipped.push({ mall: m.name, why: '이미 수집 진행 중' }); continue; }
    const jid = 'j' + now.toString(36) + hex(crypto.getRandomValues(new Uint8Array(3))) + id;
    st.push(putRec(env, user, JOB_STORE, jid, {
      id: jid, mall: id, mallName: m.name, orderMall: m.orderMall,
      from, to, status: 'pending', createdAt: now,
    }));
    created.push(m.name);
  }
  if (st.length) await env.DB.batch(st);
  return J({ ok: true, created, skipped });
}

async function listJobs(env, user) {
  const now = Date.now();
  // 도우미가 멈춰서 오래 '진행 중'으로 남은 작업은 실패 처리
  await env.DB
    .prepare("UPDATE records SET d=json_set(d,'$.status','failed','$.error','시간 초과 (도우미 프로그램이 응답하지 않았습니다)','$.finishedAt',?) WHERE u=? AND s=? AND json_extract(d,'$.status')='running' AND json_extract(d,'$.startedAt')<?")
    .bind(now, user, JOB_STORE, now - STALE_MS).run();
  const { results } = await env.DB
    .prepare('SELECT d FROM records WHERE u=? AND s=? ORDER BY rowid DESC LIMIT 60').bind(user, JOB_STORE).all();
  const meta = await getRec(env, user, META_STORE, 'worker');
  return J({ jobs: results.map((r) => JSON.parse(r.d)), workerSeen: meta ? meta.ts : null, now });
}

async function jobFile(env, user, url) {
  const id = String(url.searchParams.get('id') || '');
  const f = await getRec(env, user, FILE_STORE, id);
  if (!f) fail('파일을 찾을 수 없습니다.', 404);
  return J({ name: f.name, b64: f.b64 });
}

async function jobApplied(env, user, body) {
  const id = String((body && body.id) || '');
  const job = await getRec(env, user, JOB_STORE, id);
  if (!job) fail('작업을 찾을 수 없습니다.', 404);
  job.applied = body.state === 'needmap' ? 'needmap' : 'done';
  job.added = Number(body.added) || 0;
  job.dup = Number(body.dup) || 0;
  job.appliedAt = Date.now();
  const st = [putRec(env, user, JOB_STORE, id, job)];
  if (job.applied === 'done') st.push(delRec(env, user, FILE_STORE, id)); // 반영 끝난 파일은 삭제
  await env.DB.batch(st);
  return J({ ok: true });
}

/* ================= 도우미 프로그램(RPA 워커) 전용 ================= */
function workerUser(env, req) {
  const tok = String(env.WORKER_TOKEN || '');
  const hdr = req.headers.get('authorization') || '';
  const given = hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
  if (tok.length < 16 || !given || !same(given, tok)) return null;
  const u = String(env.WORKER_USER || '').trim().toLowerCase();
  return u || null;
}

async function workerNext(env, user) {
  const now = Date.now();
  await env.DB.batch([putRec(env, user, META_STORE, 'worker', { ts: now })]);
  const row = await env.DB
    .prepare("SELECT k, d FROM records WHERE u=? AND s=? AND json_extract(d,'$.status')='pending' ORDER BY rowid LIMIT 1")
    .bind(user, JOB_STORE).first();
  if (!row) return J({ job: null });
  const claim = await env.DB
    .prepare("UPDATE records SET d=json_set(d,'$.status','running','$.startedAt',?) WHERE u=? AND s=? AND k=? AND json_extract(d,'$.status')='pending'")
    .bind(now, user, JOB_STORE, row.k).run();
  if (!claim.meta || claim.meta.changes !== 1) return J({ job: null });
  const job = JSON.parse(row.d);
  const m = await getRec(env, user, MALL_STORE, job.mall);
  const c = await getRec(env, user, CRED_STORE, job.mall);
  if (!m || !m.loginId || !c) {
    await workerResult(env, user, { id: job.id, ok: false, error: '쇼핑몰 아이디/비밀번호가 설정되어 있지 않습니다.' });
    return J({ job: null });
  }
  const password = await decryptPw(env, user, job.mall, c.pw);
  return J({ job: { id: job.id, mall: job.mall, mallName: job.mallName, from: job.from, to: job.to }, cred: { loginId: m.loginId, password } });
}

async function workerResult(env, user, body) {
  const id = String((body && body.id) || '');
  const job = await getRec(env, user, JOB_STORE, id);
  if (!job) fail('작업을 찾을 수 없습니다.', 404);
  const now = Date.now();
  job.finishedAt = now;
  const st = [];
  if (body.ok === true) {
    const b64 = String(body.fileB64 || '');
    if (!b64) fail('파일이 없습니다.');
    if (b64.length > MAX_FILE_B64) {
      job.status = 'failed';
      job.error = '주문 파일이 너무 큽니다. 수집 기간을 나눠서 다시 시도해 주세요.';
    } else {
      job.status = 'done';
      job.fileName = String(body.fileName || 'orders.xlsx').slice(0, 120);
      job.rows = Number(body.rows) || 0;
      st.push(putRec(env, user, FILE_STORE, id, { name: job.fileName, b64 }));
    }
  } else if (body.empty === true) {
    job.status = 'done';      // 해당 기간에 주문이 없는 경우
    job.rows = 0;
    job.applied = 'done';
    job.added = 0;
  } else {
    job.status = 'failed';
    job.error = String(body.error || '알 수 없는 오류').slice(0, 300);
  }
  st.push(putRec(env, user, JOB_STORE, id, job));
  await env.DB.batch(st);
  return J({ ok: true });
}

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/mall\/?/, '').replace(/\/+$/, '');
  const method = request.method;
  if (!env.DB) return J({ error: '서버 설정 오류입니다. D1 바인딩(DB)을 확인해 주세요.' }, 500);
  try {
    // 도우미 프로그램 (토큰 인증)
    if (route.startsWith('worker/')) {
      const wu = workerUser(env, request);
      if (!wu) return J({ error: '인증 실패' }, 401);
      if (route === 'worker/next' && method === 'GET') return await workerNext(env, wu);
      if (route === 'worker/result' && method === 'POST') return await workerResult(env, wu, await readJson(request));
      return J({ error: 'Not found' }, 404);
    }

    // 브라우저 (로그인 세션)
    if (method === 'POST') {
      const o = request.headers.get('origin');
      if (o) {
        let h = '';
        try { h = new URL(o).host; } catch (e) {}
        if (h !== url.host) return J({ error: '허용되지 않은 요청입니다.' }, 403);
      }
    }
    const user = await currentUser(env, request);
    if (!user) return J({ error: '로그인이 필요합니다.' }, 401);

    if (route === 'list' && method === 'GET') return J({ malls: await listMalls(env, user) });
    if (route === 'save' && method === 'POST') return await saveMall(env, user, await readJson(request));
    if (route === 'collect' && method === 'POST') return await requestCollect(env, user, await readJson(request));
    if (route === 'jobs' && method === 'GET') return await listJobs(env, user);
    if (route === 'file' && method === 'GET') return await jobFile(env, user, url);
    if (route === 'applied' && method === 'POST') return await jobApplied(env, user, await readJson(request));
    return J({ error: 'Not found' }, 404);
  } catch (e) {
    if (e instanceof Response) return e;
    console.error(e);
    return J({ error: '서버 오류가 발생했습니다.' }, 500);
  }
}
