require('dotenv').config();
const path = require('path');
const http = require('http');
const express = require('express');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) { console.error('Missing DATABASE_URL environment variable.'); process.exit(1); }
if (!JWT_SECRET) { console.error('Missing JWT_SECRET environment variable.'); process.exit(1); }

// ---------- Database ----------
const dbUrl = new URL(DATABASE_URL);
const isLocal = ['localhost', '127.0.0.1'].includes(dbUrl.hostname);
dbUrl.searchParams.delete('sslmode');
dbUrl.searchParams.delete('channel_binding');
const pool = new Pool({
  connectionString: dbUrl.toString(),
  ssl: isLocal ? false : { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(20) NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_idx ON users (LOWER(username));
    CREATE TABLE IF NOT EXISTS friendships (
      id SERIAL PRIMARY KEY,
      requester_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      addressee_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status VARCHAR(10) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (requester_id, addressee_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS messages_pair_idx ON messages (sender_id, receiver_id, id);
  `);
  console.log('Database ready.');
}

// ---------- Helpers ----------
const sign = (u) => jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: '7d' });
const validName = (n) => typeof n === 'string' && /^[A-Za-z0-9_]{3,20}$/.test(n);
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); });

function auth(req, res, next) {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Your session expired. Please sign in again.' });
  }
}

async function areFriends(a, b) {
  const { rows } = await pool.query(
    `SELECT 1 FROM friendships WHERE status='accepted'
     AND ((requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1))`, [a, b]);
  return rows.length > 0;
}

async function friendIds(userId) {
  const { rows } = await pool.query(
    `SELECT CASE WHEN requester_id=$1 THEN addressee_id ELSE requester_id END AS id
     FROM friendships WHERE status='accepted' AND (requester_id=$1 OR addressee_id=$1)`, [userId]);
  return rows.map((r) => r.id);
}

// userId -> Set of socket ids (a user can have several tabs/devices)
const online = new Map();
const isOnline = (id) => online.has(id);

// ---------- App ----------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/register', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (!validName(username)) return res.status(400).json({ error: 'Username must be 3–20 letters, numbers or underscores.' });
  if (typeof password !== 'string' || password.length < 6 || password.length > 72)
    return res.status(400).json({ error: 'Password must be 6–72 characters.' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username', [username, hash]);
    res.json({ token: sign(rows[0]), user: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That username is already taken.' });
    throw e;
  }
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Enter your username and password.' });
  const { rows } = await pool.query('SELECT * FROM users WHERE LOWER(username)=LOWER($1)', [username]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password, u.password_hash)))
    return res.status(401).json({ error: 'Incorrect username or password.' });
  res.json({ token: sign(u), user: { id: u.id, username: u.username } });
}));

app.get('/api/me', auth, (req, res) => res.json({ user: { id: req.user.id, username: req.user.username } }));

app.get('/api/users/search', auth, wrap(async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 20);
  if (!q) return res.json({ users: [] });
  const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
  const { rows } = await pool.query(
    `SELECT u.id, u.username, f.status, f.requester_id
     FROM users u
     LEFT JOIN friendships f ON (f.requester_id=u.id AND f.addressee_id=$1) OR (f.requester_id=$1 AND f.addressee_id=u.id)
     WHERE u.id<>$1 AND u.username ILIKE $2 ORDER BY u.username LIMIT 10`, [req.user.id, like]);
  res.json({ users: rows });
}));

app.get('/api/friends', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username FROM friendships f
     JOIN users u ON u.id = CASE WHEN f.requester_id=$1 THEN f.addressee_id ELSE f.requester_id END
     WHERE f.status='accepted' AND (f.requester_id=$1 OR f.addressee_id=$1) ORDER BY u.username`, [req.user.id]);
  res.json({ friends: rows.map((r) => ({ ...r, online: isOnline(r.id) })) });
}));

app.get('/api/requests', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT f.id, u.id AS "userId", u.username FROM friendships f
     JOIN users u ON u.id=f.requester_id WHERE f.addressee_id=$1 AND f.status='pending' ORDER BY f.created_at`, [req.user.id]);
  res.json({ requests: rows });
}));

app.get('/api/messages/:friendId', auth, wrap(async (req, res) => {
  const other = Number(req.params.friendId);
  if (!other || !(await areFriends(req.user.id, other))) return res.status(403).json({ error: 'You can only view chats with friends.' });
  const { rows } = await pool.query(
    `SELECT * FROM (
       SELECT id, sender_id, receiver_id, content, created_at FROM messages
       WHERE (sender_id=$1 AND receiver_id=$2) OR (sender_id=$2 AND receiver_id=$1)
       ORDER BY id DESC LIMIT 200
     ) t ORDER BY id ASC`, [req.user.id, other]);
  res.json({ messages: rows });
}));

// ---------- Socket.IO ----------
io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth && socket.handshake.auth.token, JWT_SECRET);
    next();
  } catch {
    next(new Error('auth'));
  }
});

async function broadcastPresence(userId, isOn) {
  for (const id of await friendIds(userId)) io.to('u:' + id).emit('presence', { userId, online: isOn });
}

io.on('connection', (socket) => {
  const me = socket.user.id;
  const myName = socket.user.username;
  const reply = (cb, obj) => { if (typeof cb === 'function') cb(obj); };
  const on = (event, fn) => socket.on(event, async (data, cb) => {
    try { reply(cb, (await fn(data || {})) || { ok: true }); }
    catch (e) { console.error(event, e); reply(cb, { error: 'Server error. Please try again.' }); }
  });

  socket.join('u:' + me);
  if (!online.has(me)) online.set(me, new Set());
  const sockets = online.get(me);
  sockets.add(socket.id);
  if (sockets.size === 1) broadcastPresence(me, true).catch(console.error);

  on('friend:request', async ({ userId }) => {
    userId = Number(userId);
    if (!userId || userId === me) return { error: 'Invalid user.' };
    const target = (await pool.query('SELECT id FROM users WHERE id=$1', [userId])).rows[0];
    if (!target) return { error: 'User not found.' };
    const ex = (await pool.query(
      `SELECT * FROM friendships WHERE (requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1)`,
      [me, userId])).rows[0];
    if (ex) {
      if (ex.status === 'accepted') return { error: 'You are already friends.' };
      return { error: ex.requester_id === me ? 'Request already sent.' : 'They already sent you a request. Check your pending requests.' };
    }
    const { rows } = await pool.query(
      'INSERT INTO friendships (requester_id, addressee_id) VALUES ($1, $2) RETURNING id', [me, userId]);
    io.to('u:' + userId).emit('request:incoming', { id: rows[0].id, userId: me, username: myName });
    return { ok: true };
  });

  on('friend:accept', async ({ requestId }) => {
    const { rows } = await pool.query(
      `UPDATE friendships SET status='accepted' WHERE id=$1 AND addressee_id=$2 AND status='pending' RETURNING requester_id`,
      [Number(requestId), me]);
    if (!rows[0]) return { error: 'That request no longer exists.' };
    const otherId = rows[0].requester_id;
    const other = (await pool.query('SELECT id, username FROM users WHERE id=$1', [otherId])).rows[0];
    io.to('u:' + me).emit('friend:added', { requestId: Number(requestId), friend: { ...other, online: isOnline(otherId) } });
    io.to('u:' + otherId).emit('friend:added', { requestId: Number(requestId), friend: { id: me, username: myName, online: true } });
    return { ok: true };
  });

  on('friend:decline', async ({ requestId }) => {
    const { rows } = await pool.query(
      `DELETE FROM friendships WHERE id=$1 AND addressee_id=$2 AND status='pending' RETURNING id`, [Number(requestId), me]);
    if (!rows[0]) return { error: 'That request no longer exists.' };
    io.to('u:' + me).emit('request:removed', { requestId: Number(requestId) });
    return { ok: true };
  });

  on('message:send', async ({ to, content }) => {
    to = Number(to);
    content = typeof content === 'string' ? content.trim() : '';
    if (!to || !content) return { error: 'Write a message first.' };
    if (content.length > 2000) return { error: 'Messages can be up to 2000 characters.' };
    if (!(await areFriends(me, to))) return { error: 'You can only message friends.' };
    const { rows } = await pool.query(
      `INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3)
       RETURNING id, sender_id, receiver_id, content, created_at`, [me, to, content]);
    io.to('u:' + me).to('u:' + to).emit('message', rows[0]);
    return { ok: true };
  });

  socket.on('typing', async (data) => {
    try {
      const to = Number(data && data.to);
      if (to && (await areFriends(me, to))) io.to('u:' + to).emit('typing', { from: me, isTyping: !!data.isTyping });
    } catch (e) { console.error('typing', e); }
  });

  socket.on('disconnect', () => {
    sockets.delete(socket.id);
    if (sockets.size === 0) {
      online.delete(me);
      broadcastPresence(me, false).catch(console.error);
    }
  });
});

// ---------- Start ----------
initDb()
  .then(() => server.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
  .catch((e) => { console.error('Failed to start:', e); process.exit(1); });
