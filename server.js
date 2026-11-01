/**
 * 픽셀 로그 백엔드 서버
 * - Node.js + Express + SQLite
 * - 실행:  npm install  →  node server.js  →  http://localhost:3000
 *
 * 데이터베이스는 Node.js에 내장된 node:sqlite를 사용합니다.
 * (예전 Node 버전이면 better-sqlite3가 설치되어 있을 때 그것으로 대체됩니다)
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

/* .env 읽기 (KEY=값 한 줄씩) — 라이브러리 없이 간단히 */
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch (e) { /* .env가 없으면 그냥 넘어감 */ }

/* ===== 데이터베이스 연결 ===== */
const DB_FILE = path.join(__dirname, 'pixellog.db');
let db;
try {
  const { DatabaseSync } = require('node:sqlite');     // Node 22 이상 내장
  db = new DatabaseSync(DB_FILE);
} catch (e) {
  const Database = require('better-sqlite3');          // 예전 Node용
  db = new Database(DB_FILE);
}

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  email      TEXT UNIQUE NOT NULL,
  password   TEXT NOT NULL,              -- bcrypt로 해시해서 저장
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (      -- 로그인 상태(간단한 세션 토큰)
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (    -- 사용자별 설정
  user_id      INTEGER PRIMARY KEY,
  base_habits  TEXT NOT NULL,            -- JSON 배열
  notify_time  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS growth (      -- 성장 상태
  user_id     INTEGER PRIMARY KEY,
  stage       INTEGER NOT NULL DEFAULT 0,
  filled      INTEGER NOT NULL DEFAULT 0,
  miss_streak INTEGER NOT NULL DEFAULT 0,
  dust_lv     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS records (     -- 날짜별 기록 (하루 = 한 줄)
  user_id     INTEGER NOT NULL,
  date        TEXT NOT NULL,             -- 'YYYY-MM-DD' (로컬 시간 기준)
  cond        TEXT,                      -- good/normal/tired/sad/angry/sick
  memo        TEXT,
  items       TEXT,                      -- 체크리스트 JSON
  care        TEXT,                      -- 돌봄 항목 JSON
  stamped     INTEGER DEFAULT 0,         -- 돌봄 도장
  grew        INTEGER DEFAULT 0,         -- 그날 게이지를 올렸는지
  chance_used INTEGER DEFAULT 0,
  missed      INTEGER DEFAULT 0,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (user_id, date)
);
`);

const run = (sql, ...args) => db.prepare(sql).run(...args);
const get = (sql, ...args) => db.prepare(sql).get(...args);
const all = (sql, ...args) => db.prepare(sql).all(...args);

/* ===== 로그인 확인 ===== */
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const row = token && get('SELECT user_id FROM tokens WHERE token = ?', token);
  if (!row) return res.status(401).json({ error: '로그인이 필요합니다' });
  req.userId = row.user_id;
  next();
}
function issueToken(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  run('INSERT INTO tokens (token, user_id, created_at) VALUES (?, ?, ?)', token, userId, new Date().toISOString());
  return token;
}

/* ===== 서버가 살아 있는지 확인 (앱이 시작할 때 한 번) ===== */
app.get('/api/ping', (req, res) => res.json({ ok: true }));

/* ===== 회원가입 · 로그인 ===== */
app.post('/api/signup', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: '이메일과 비밀번호를 입력해주세요' });
  if (password.length < 4) return res.status(400).json({ error: '비밀번호는 4자 이상이어야 합니다' });
  if (get('SELECT id FROM users WHERE email = ?', email)) return res.status(409).json({ error: '이미 가입된 이메일입니다' });

  const hash = bcrypt.hashSync(password, 10);
  const info = run('INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)', email, hash, new Date().toISOString());
  const userId = Number(info.lastInsertRowid);

  // 습관 목록은 비워 둔다 → 앱이 '처음 설정' 화면을 띄운다
  run('INSERT INTO settings (user_id, base_habits, notify_time) VALUES (?, ?, ?)',
      userId, '[]', '21:00');
  run('INSERT INTO growth (user_id) VALUES (?)', userId);

  res.json({ token: issueToken(userId), email });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = get('SELECT * FROM users WHERE email = ?', email || '');
  if (!user || !bcrypt.compareSync(password || '', user.password))
    return res.status(401).json({ error: '이메일 또는 비밀번호가 맞지 않습니다' });
  res.json({ token: issueToken(user.id), email: user.email });
});

app.post('/api/logout', auth, (req, res) => {
  run('DELETE FROM tokens WHERE token = ?', (req.headers.authorization || '').replace('Bearer ', ''));
  res.json({ ok: true });
});

/* ===== 기록 불러오기 (앱을 열 때 한 번) ===== */
app.get('/api/state', auth, (req, res) => {
  const s = get('SELECT * FROM settings WHERE user_id = ?', req.userId);
  const g = get('SELECT * FROM growth WHERE user_id = ?', req.userId);
  const rows = all('SELECT * FROM records WHERE user_id = ?', req.userId);

  const days = {};
  for (const r of rows) {
    days[r.date] = {
      cond: r.cond, memo: r.memo || '',
      items: JSON.parse(r.items || '[]'),
      care: JSON.parse(r.care || '[]'),
      stamped: !!r.stamped, grew: !!r.grew,
      chanceUsed: !!r.chance_used, missed: !!r.missed,
      picked: [], picking: false
    };
  }
  res.json({
    settings: { baseHabits: JSON.parse(s.base_habits), notifyTime: s.notify_time },
    growth: { stage: g.stage, filled: g.filled, missStreak: g.miss_streak, dustLv: g.dust_lv },
    days
  });
});

/* ===== 하루 기록 저장 (날짜 한 줄씩 UPSERT) ===== */
app.put('/api/records/:date', auth, (req, res) => {
  const d = req.body || {};
  if (!/^\d{4}-\d{2}-\d{2}$/.test(req.params.date))
    return res.status(400).json({ error: '날짜 형식은 YYYY-MM-DD 입니다' });

  run(`INSERT INTO records (user_id, date, cond, memo, items, care, stamped, grew, chance_used, missed, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id, date) DO UPDATE SET
         cond=excluded.cond, memo=excluded.memo, items=excluded.items, care=excluded.care,
         stamped=excluded.stamped, grew=excluded.grew, chance_used=excluded.chance_used,
         missed=excluded.missed, updated_at=excluded.updated_at`,
    req.userId, req.params.date, d.cond || null, d.memo || '',
    JSON.stringify(d.items || []), JSON.stringify(d.care || []),
    d.stamped ? 1 : 0, d.grew ? 1 : 0, d.chanceUsed ? 1 : 0, d.missed ? 1 : 0,
    new Date().toISOString());
  res.json({ ok: true });
});

/* ===== 성장 상태 저장 ===== */
app.put('/api/growth', auth, (req, res) => {
  const g = req.body || {};
  run('UPDATE growth SET stage=?, filled=?, miss_streak=?, dust_lv=? WHERE user_id=?',
      g.stage | 0, g.filled | 0, g.missStreak | 0, g.dustLv | 0, req.userId);
  res.json({ ok: true });
});

/* ===== 설정 저장 ===== */
app.put('/api/settings', auth, (req, res) => {
  const s = req.body || {};
  run('UPDATE settings SET base_habits=?, notify_time=? WHERE user_id=?',
      JSON.stringify(s.baseHabits || []), s.notifyTime || '21:00', req.userId);
  res.json({ ok: true });
});

/* ===== 달력용: 특정 달의 기록만 조회 ===== */
app.get('/api/records', auth, (req, res) => {
  const month = req.query.month || '';   // 예: 2026-10
  res.json(all(
    'SELECT date, cond, stamped, chance_used, missed FROM records WHERE user_id=? AND date LIKE ? ORDER BY date',
    req.userId, month + '%'));
});

/* ===== AI 한 달 돌아보기 =====
 * 마인드로직 API 게이트웨이(OpenAI 호환)를 호출합니다.
 * 보내는 것은 '이미 계산해 둔 숫자'뿐입니다. 메모 본문은 보내지 않습니다.
 * 키가 없거나 호출이 실패하면 규칙으로 만든 문장으로 대신합니다.
 */
const AI_BASE  = process.env.MINDLOGIC_URL   || 'https://factchat-cloud.mindlogic.ai/v1/gateway';
const AI_MODEL = process.env.MINDLOGIC_MODEL || 'solar-pro4';
const AI_KEY   = process.env.MINDLOGIC_API_KEY || '';

const COND_NAME  = { good:'좋음', normal:'보통', tired:'피곤', sad:'우울', angry:'화남', sick:'아픔' };
const STAGE_NAME = ['알','부화','아기','어린이','청소년','어른','노인'];

function monthStats(userId, month) {
  const rows = all('SELECT * FROM records WHERE user_id=? AND date LIKE ? ORDER BY date', userId, month + '%');
  const g = get('SELECT * FROM growth WHERE user_id=?', userId) || { stage: 0, filled: 0 };
  const conds = {};
  let days = 0, stamps = 0, chance = 0, missed = 0, grew = 0;
  for (const r of rows) {
    if (r.cond) { const n = COND_NAME[r.cond] || r.cond; conds[n] = (conds[n] || 0) + 1; days++; }
    if (r.stamped)     stamps++;
    if (r.chance_used) chance++;
    if (r.missed)      missed++;
    if (r.grew)        grew++;
  }
  return { 월: month, 기록한_날: days, 컨디션별_일수: conds, 성장한_칸: grew,
           돌봄_도장: stamps, 기회_사용: chance, 빠진_날: missed,
           현재_단계: STAGE_NAME[g.stage] || '알', 현재_게이지: g.filled };
}

function ruleSummary(s) {
  const top = Object.entries(s.컨디션별_일수).sort((a, b) => b[1] - a[1])[0];
  const out = [`이번 달은 ${s.기록한_날}일 기록했어요.`];
  if (top) out.push(`${top[0]}인 날이 ${top[1]}일로 가장 많았어요.`);
  out.push(`성장 게이지는 ${s.성장한_칸}칸 올랐고, 돌봄 도장은 ${s.돌봄_도장}개예요.`);
  if (s.빠진_날) out.push(`빠진 날이 ${s.빠진_날}일 있었지만 다시 돌아왔네요.`);
  return out.join(' ');
}

const AI_SYSTEM = [
  "당신은 습관 다이어리 앱 '픽셀 로그'의 월말 돌아보기를 써 주는 도우미입니다.",
  '- 사용자가 준 숫자만 사용하세요. 없는 숫자나 사건을 지어내지 마세요.',
  '- 한국어 존댓말로 3~4문장, 전체 200자 이내로 쓰세요.',
  '- 잘한 점 하나, 눈에 띄는 흐름 하나, 다음 달에 해볼 만한 것 하나를 담으세요.',
  '- 건강이나 심리 상태를 진단하지 말고, 의학적 조언도 하지 마세요.',
  '- 과장된 칭찬이나 훈계는 쓰지 말고 담백하게 쓰세요.',
  '- 목록이나 제목 없이 문단 하나로만 쓰세요.'
].join('\n');

app.get('/api/ai/status', auth, (req, res) => res.json({ enabled: !!AI_KEY, model: AI_MODEL }));

app.post('/api/ai/summary', auth, async (req, res) => {
  const month = String((req.body || {}).month || '');
  if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: 'month 형식은 YYYY-MM 입니다' });

  const stats = monthStats(req.userId, month);
  if (!stats.기록한_날) return res.json({ sent: stats, text: '이번 달에는 아직 기록이 없어요.', by: 'rule' });
  if (!AI_KEY)          return res.json({ sent: stats, text: ruleSummary(stats), by: 'rule',
                                          note: 'MINDLOGIC_API_KEY가 설정되지 않아 규칙 문장으로 대신했습니다' });

  try {
    const r = await fetch(AI_BASE.replace(/\/+$/, '') + '/chat/completions/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + AI_KEY },
      body: JSON.stringify({
        model: AI_MODEL,
        messages: [
          { role: 'system', content: AI_SYSTEM },
          { role: 'user',   content: '이번 달 기록 통계입니다.\n' + JSON.stringify(stats, null, 1) }
        ],
        max_tokens: 400,
        temperature: 0.7
      })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.error && data.error.message) || data.detail || `요청 실패 (${r.status})`);
    const text = data.choices && data.choices[0] && data.choices[0].message
               && String(data.choices[0].message.content || '').trim();
    if (!text) throw new Error('빈 응답');
    res.json({ sent: stats, text, by: AI_MODEL });
  } catch (e) {
    res.json({ sent: stats, text: ruleSummary(stats), by: 'rule', error: String(e.message || e) });
  }
});

/* ===== AI 캐릭터 한마디 =====
 * 컨디션을 저장할 때 하루 한 번. 숫자만 보내고, 메모는 사용자가 켰을 때만 보냅니다.
 */
function shiftKey(k, delta) {
  const [y, m, d] = k.split('-').map(Number);
  const dt = new Date(y, m - 1, d + delta), p = n => String(n).padStart(2, '0');
  return `${dt.getFullYear()}-${p(dt.getMonth() + 1)}-${p(dt.getDate())}`;
}

function dayInfo(userId, date, withMemo) {
  const r = get('SELECT * FROM records WHERE user_id=? AND date=?', userId, date) || {};
  const g = get('SELECT * FROM growth WHERE user_id=?', userId) || { stage: 0, filled: 0, dust_lv: 0 };
  const items = JSON.parse(r.items || '[]'), care = JSON.parse(r.care || '[]');

  const recent = [];
  let hard = 0, streak = 0, hardOpen = true, streakOpen = true;
  for (let i = 0; i < 7; i++) {
    const row = i === 0 ? r : (get('SELECT cond FROM records WHERE user_id=? AND date=?', userId, shiftKey(date, -i)) || {});
    recent.push(row.cond ? (COND_NAME[row.cond] || row.cond) : '없음');
    if (streakOpen && row.cond) streak++; else streakOpen = false;
    if (hardOpen && ['sad', 'angry', 'sick'].includes(row.cond)) hard++; else hardOpen = false;
  }

  // 오늘 전에 기록 없이 비어 있던 날 수 (먼지는 저장할 때 이미 털리므로, 돌아온 날은 이걸로 안다)
  let gap = 0;
  if (get('SELECT 1 AS x FROM records WHERE user_id=? AND date<? AND cond IS NOT NULL LIMIT 1', userId, date)) {
    for (let i = 1; i <= 60; i++) {
      const row = get('SELECT cond FROM records WHERE user_id=? AND date=?', userId, shiftKey(date, -i)) || {};
      if (row.cond) break;
      gap++;
    }
  }

  const info = {
    컨디션: r.cond ? (COND_NAME[r.cond] || r.cond) : '없음',
    직전_빈_날: gap,
    성장_단계: STAGE_NAME[g.stage] || '알',
    오늘_완료: items.filter(i => i.done).length,
    오늘_항목수: items.length,
    돌봄_완료: care.filter(c => c.done).length,
    오늘_성장함: !!r.grew,
    먼지_단계: g.dust_lv || 0,
    연속_기록일: streak,
    힘든_날_연속: hard,
    최근_7일: recent
  };
  if (withMemo && r.memo) info.메모 = r.memo;
  return info;
}

const SAY_FALLBACK = {
  좋음:   ['오늘 기분 좋아 보인다! 나도 좋아', '이런 날이 자주 왔으면 좋겠다'],
  보통:   ['오늘도 와줘서 고마워', '별일 없는 날도 괜찮지'],
  피곤:   ['오늘은 좀 피곤했구나. 푹 자', '무리하지 말고 쉬어'],
  우울:   ['오늘 마음이 좀 무거웠구나. 옆에 있을게', '힘든 날도 기록해줘서 고마워'],
  화남:   ['화나는 일이 있었구나. 숨 한 번 크게 쉬자', '오늘은 그럴 수도 있지'],
  아픔:   ['아프구나… 오늘은 쉬는 게 일이야', '몸부터 챙겨. 나는 기다릴게'],
  없음:   ['오늘은 어땠어?']
};
function sayFallback(info) {
  const list = SAY_FALLBACK[info.컨디션] || SAY_FALLBACK.없음;
  if (info.힘든_날_연속 >= 3) return '요즘 계속 힘들었구나. 혼자 끙끙대지 말고 누구한테든 얘기해봐';
  if (info.직전_빈_날 >= 2 && info.컨디션 !== '없음') return '돌아왔다! 먼지 털자, 기다렸어';
  return list[(info.연속_기록일 + info.오늘_완료) % list.length];
}

const SAY_SYSTEM = [
  "당신은 습관 다이어리 앱 '픽셀 로그'의 픽셀 강아지 캐릭터입니다. 사용자에게 한마디를 건넵니다.",
  '- 1~2문장, 전체 40자 안팎으로 아주 짧게 쓰세요.',
  '- 강아지가 말하듯 친근한 반말로 쓰세요. 이모지는 최대 1개까지만.',
  '- 받은 숫자만 근거로 쓰세요. 없는 사실이나 사건을 지어내지 마세요.',
  '- 건강이나 마음 상태를 진단하지 말고, 의학적 조언도 하지 마세요.',
  '- 더 하라고 몰아붙이거나 훈계하지 마세요. 못 한 것을 지적하지 마세요.',
  '- 직전_빈_날이 2 이상이면 다시 돌아온 것을 반갑게 맞아 주세요. 빠진 날을 탓하지 마세요.',
  '- 힘든_날_연속이 3 이상일 때만, 혼자 힘들면 주변 사람에게 얘기해보라는 말을 자연스럽게 한 번 섞으세요. 그 외에는 넣지 마세요.',
  '- 따옴표나 제목 없이 문장만 쓰세요.'
].join('\n');

app.post('/api/ai/say', auth, async (req, res) => {
  const body = req.body || {};
  const date = String(body.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'date 형식은 YYYY-MM-DD 입니다' });

  const info = dayInfo(req.userId, date, !!body.includeMemo);
  if (!AI_KEY) return res.json({ sent: info, text: sayFallback(info), by: 'rule' });

  try {
    const r = await fetch(AI_BASE.replace(/\/+$/, '') + '/chat/completions/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + AI_KEY },
      body: JSON.stringify({
        model: AI_MODEL,
        messages: [
          { role: 'system', content: SAY_SYSTEM },
          { role: 'user',   content: '오늘 상태입니다.\n' + JSON.stringify(info, null, 1) }
        ],
        max_tokens: 150,
        temperature: 0.9
      })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.error && data.error.message) || data.detail || `요청 실패 (${r.status})`);
    let text = data.choices && data.choices[0] && data.choices[0].message
             && String(data.choices[0].message.content || '').trim();
    if (!text) throw new Error('빈 응답');
    text = text.replace(/^["'「『]|["'」』]$/g, '').split('\n')[0].trim();
    if (text.length > 60) text = text.slice(0, 60).trim();     // 한 줄을 넘지 않게
    res.json({ sent: info, text, by: AI_MODEL });
  } catch (e) {
    res.json({ sent: info, text: sayFallback(info), by: 'rule', error: String(e.message || e) });
  }
});

app.listen(PORT, () => {
  console.log(`픽셀 로그 서버: http://localhost:${PORT}`);
  console.log(AI_KEY ? `AI 요약: 켜짐 (${AI_MODEL})`
                     : 'AI 요약: 꺼짐 — .env에 MINDLOGIC_API_KEY를 넣으면 켜집니다');
});
