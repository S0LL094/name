require('dotenv').config();
const path = require('path');
const http = require('http');
const express = require('express');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

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
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar BYTEA;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_v INT NOT NULL DEFAULT 0;
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
    CREATE TABLE IF NOT EXISTS servers (
      id SERIAL PRIMARY KEY,
      name VARCHAR(30) NOT NULL,
      owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      invite_code VARCHAR(16) NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS server_members (
      server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (server_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS channels (
      id SERIAL PRIMARY KEY,
      server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      name VARCHAR(30) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (server_id, name)
    );
    CREATE TABLE IF NOT EXISTS channel_messages (
      id SERIAL PRIMARY KEY,
      channel_id INT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS channel_messages_idx ON channel_messages (channel_id, id);
    ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_group BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS blocks (
      blocker_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      blocked_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (blocker_id, blocked_id)
    );
    ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMPTZ;
    ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS reply_to INT;
    ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE channel_messages ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS message_reactions (
      message_id INT NOT NULL REFERENCES channel_messages(id) ON DELETE CASCADE,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      emoji VARCHAR(16) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (message_id, user_id, emoji)
    );
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
const getAv = async (id) => ((await pool.query('SELECT avatar_v FROM users WHERE id=$1', [id])).rows[0] || {}).avatar_v || 0;

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
    res.json({ token: sign(rows[0]), user: { ...rows[0], av: 0 } });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That username is already taken.' });
    throw e;
  }
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'Enter your username and password.' });
  const { rows } = await pool.query('SELECT id, username, password_hash, avatar_v FROM users WHERE LOWER(username)=LOWER($1)', [username]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password, u.password_hash)))
    return res.status(401).json({ error: 'Incorrect username or password.' });
  res.json({ token: sign(u), user: { id: u.id, username: u.username, av: u.avatar_v } });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, avatar_v AS av FROM users WHERE id=$1', [req.user.id]);
  if (!rows[0]) return res.status(401).json({ error: 'Your session expired. Please sign in again.' });
  res.json({ user: rows[0] });
}));

app.get('/avatar/:id', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT avatar FROM users WHERE id=$1', [Number(req.params.id) || 0]);
  if (!rows[0] || !rows[0].avatar) return res.status(404).end();
  res.set({ 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=31536000, immutable', 'X-Content-Type-Options': 'nosniff' });
  res.send(rows[0].avatar);
}));

app.get('/api/users/search', auth, wrap(async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 20);
  if (!q) return res.json({ users: [] });
  const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.avatar_v AS av, f.status, f.requester_id
     FROM users u
     LEFT JOIN friendships f ON (f.requester_id=u.id AND f.addressee_id=$1) OR (f.requester_id=$1 AND f.addressee_id=u.id)
     WHERE u.id<>$1 AND u.username ILIKE $2
     AND NOT EXISTS (SELECT 1 FROM blocks b WHERE (b.blocker_id=u.id AND b.blocked_id=$1) OR (b.blocker_id=$1 AND b.blocked_id=u.id))
     ORDER BY u.username LIMIT 10`, [req.user.id, like]);
  res.json({ users: rows });
}));

app.get('/api/friends', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.avatar_v AS av,
     (SELECT MAX(created_at) FROM messages WHERE (sender_id=$1 AND receiver_id=u.id) OR (sender_id=u.id AND receiver_id=$1)) AS last
     FROM friendships f
     JOIN users u ON u.id = CASE WHEN f.requester_id=$1 THEN f.addressee_id ELSE f.requester_id END
     WHERE f.status='accepted' AND (f.requester_id=$1 OR f.addressee_id=$1) ORDER BY u.username`, [req.user.id]);
  res.json({ friends: rows.map((r) => ({ ...r, online: isOnline(r.id) })) });
}));

app.get('/api/blocks', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT u.id, u.username, u.avatar_v AS av FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.blocker_id=$1 ORDER BY u.username', [req.user.id]);
  res.json({ users: rows });
}));

app.get('/api/requests', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT f.id, u.id AS "userId", u.username, u.avatar_v AS av FROM friendships f
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

// ---------- Servers ----------
const MSG_SQL = `SELECT m.id, m.channel_id, m.sender_id, u.username, u.avatar_v AS av, m.content, m.created_at,
  m.edited_at, m.pinned, m.is_system, m.reply_to, LEFT(r.content, 120) AS reply_content, ru.username AS reply_username
  FROM channel_messages m JOIN users u ON u.id=m.sender_id
  LEFT JOIN channel_messages r ON r.id=m.reply_to LEFT JOIN users ru ON ru.id=r.sender_id`;

async function withReactions(rows) {
  if (!rows.length) return rows;
  const { rows: rx } = await pool.query(
    `SELECT r.message_id, r.emoji, array_agg(r.user_id) AS ids, array_agg(u.username) AS names
     FROM message_reactions r JOIN users u ON u.id=r.user_id WHERE r.message_id = ANY($1)
     GROUP BY r.message_id, r.emoji ORDER BY MIN(r.created_at)`, [rows.map((m) => m.id)]);
  for (const m of rows) m.reactions = rx.filter((x) => x.message_id === m.id).map((x) => ({ e: x.emoji, ids: x.ids, names: x.names }));
  return rows;
}
const getMessage = async (id) => (await withReactions((await pool.query(MSG_SQL + ' WHERE m.id=$1', [id])).rows))[0];
const chServer = async (cid) => ((await pool.query('SELECT server_id FROM channels WHERE id=$1', [cid])).rows[0] || {}).server_id;

app.get('/api/channels/:id/pins', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const sid = id && (await chServer(id));
  if (!sid || !(await isMember(req.user.id, sid))) return res.status(403).json({ error: 'You cannot view this channel.' });
  const { rows } = await pool.query(MSG_SQL + ' WHERE m.channel_id=$1 AND m.pinned ORDER BY m.id DESC', [id]);
  res.json({ messages: await withReactions(rows) });
}));
const isMember = async (userId, serverId) =>
  (await pool.query('SELECT 1 FROM server_members WHERE user_id=$1 AND server_id=$2', [userId, serverId])).rowCount > 0;

app.get('/api/servers', auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT s.id, s.name, s.owner_id, s.invite_code, s.is_group,
       (SELECT MAX(cm.created_at) FROM channel_messages cm JOIN channels c ON c.id=cm.channel_id WHERE c.server_id=s.id) AS last
     FROM servers s
     JOIN server_members m ON m.server_id=s.id WHERE m.user_id=$1 ORDER BY s.created_at`, [req.user.id]);
  res.json({ servers: rows });
}));

app.get('/api/servers/:id', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  if (!id || !(await isMember(req.user.id, id))) return res.status(403).json({ error: 'You are not in that server.' });
  const [ch, mem] = await Promise.all([
    pool.query('SELECT id, name FROM channels WHERE server_id=$1 ORDER BY id', [id]),
    pool.query('SELECT u.id, u.username, u.avatar_v AS av FROM server_members m JOIN users u ON u.id=m.user_id WHERE m.server_id=$1 ORDER BY u.username', [id]),
  ]);
  res.json({ channels: ch.rows, members: mem.rows.map((r) => ({ ...r, online: isOnline(r.id) })) });
}));

app.get('/api/channels/:id/messages', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  const c = id && (await pool.query('SELECT server_id FROM channels WHERE id=$1', [id])).rows[0];
  if (!c || !(await isMember(req.user.id, c.server_id))) return res.status(403).json({ error: 'You cannot view this channel.' });
  const before = Number(req.query.before) || 2147483647;
  const { rows } = await pool.query(
    `SELECT * FROM (${MSG_SQL} WHERE m.channel_id=$1 AND m.id<$2 ORDER BY m.id DESC LIMIT 50) t ORDER BY id ASC`, [id, before]);
  res.json({ messages: await withReactions(rows), more: rows.length === 50 });
}));

// ---------- Socket.IO ----------
io.use(async (socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth && socket.handshake.auth.token, JWT_SECRET);
  } catch {
    return next(new Error('auth'));
  }
  try {
    const { rows } = await pool.query('SELECT server_id FROM server_members WHERE user_id=$1', [socket.user.id]);
    if (rows.length) socket.join(rows.map((r) => 's:' + r.server_id));
  } catch (e) { console.error('join rooms', e); }
  next();
});

async function broadcastToRelated(userId, event, payload) {
  for (const id of await friendIds(userId)) io.to('u:' + id).emit(event, payload);
  const { rows } = await pool.query('SELECT server_id FROM server_members WHERE user_id=$1', [userId]);
  for (const r of rows) io.to('s:' + r.server_id).emit(event, payload);
}
const broadcastPresence = (userId, isOn) => broadcastToRelated(userId, 'presence', { userId, online: isOn });

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
    if ((await pool.query('SELECT 1 FROM blocks WHERE (blocker_id=$1 AND blocked_id=$2) OR (blocker_id=$2 AND blocked_id=$1)', [me, userId])).rowCount)
      return { error: 'You cannot send a friend request to this user.' };
    const ex = (await pool.query(
      `SELECT * FROM friendships WHERE (requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1)`,
      [me, userId])).rows[0];
    if (ex) {
      if (ex.status === 'accepted') return { error: 'You are already friends.' };
      return { error: ex.requester_id === me ? 'Request already sent.' : 'They already sent you a request. Check your pending requests.' };
    }
    const { rows } = await pool.query(
      'INSERT INTO friendships (requester_id, addressee_id) VALUES ($1, $2) RETURNING id', [me, userId]);
    io.to('u:' + userId).emit('request:incoming', { id: rows[0].id, userId: me, username: myName, av: await getAv(me) });
    return { ok: true };
  });

  on('friend:accept', async ({ requestId }) => {
    const { rows } = await pool.query(
      `UPDATE friendships SET status='accepted' WHERE id=$1 AND addressee_id=$2 AND status='pending' RETURNING requester_id`,
      [Number(requestId), me]);
    if (!rows[0]) return { error: 'That request no longer exists.' };
    const otherId = rows[0].requester_id;
    const other = (await pool.query('SELECT id, username, avatar_v AS av FROM users WHERE id=$1', [otherId])).rows[0];
    io.to('u:' + me).emit('friend:added', { requestId: Number(requestId), friend: { ...other, online: isOnline(otherId) } });
    io.to('u:' + otherId).emit('friend:added', { requestId: Number(requestId), friend: { id: me, username: myName, online: true, av: await getAv(me) } });
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

  on('avatar:set', async ({ image }) => {
    let buf = null;
    if (image !== null) {
      const m = typeof image === 'string' && /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(image);
      buf = m && Buffer.from(m[1], 'base64');
      if (!buf || buf.length > 150 * 1024 || buf[0] !== 0xff || buf[1] !== 0xd8) return { error: 'Please choose a valid image.' };
    }
    const { rows } = await pool.query(
      'UPDATE users SET avatar=$1, avatar_v=$2 WHERE id=$3 RETURNING avatar_v AS av',
      [buf, buf ? Math.floor(Date.now() / 1000) : 0, me]);
    const ev = { userId: me, av: rows[0].av };
    io.to('u:' + me).emit('avatar:updated', ev);
    await broadcastToRelated(me, 'avatar:updated', ev);
  });

  on('server:create', async ({ name }) => {
    name = typeof name === 'string' ? name.trim() : '';
    if (!name || name.length > 30) return { error: 'Server names must be 1–30 characters.' };
    const s = (await pool.query(
      'INSERT INTO servers (name, owner_id, invite_code) VALUES ($1,$2,$3) RETURNING id, name, owner_id, invite_code, is_group',
      [name, me, crypto.randomBytes(4).toString('hex')])).rows[0];
    await pool.query('INSERT INTO server_members (server_id, user_id) VALUES ($1,$2)', [s.id, me]);
    await pool.query("INSERT INTO channels (server_id, name) VALUES ($1, 'general')", [s.id]);
    io.in('u:' + me).socketsJoin('s:' + s.id);
    io.to('u:' + me).emit('server:added', { server: s });
    return { ok: true, serverId: s.id };
  });

  on('server:join', async ({ code }) => {
    code = typeof code === 'string' ? code.trim().toLowerCase() : '';
    const s = code && (await pool.query('SELECT id, name, owner_id, invite_code, is_group FROM servers WHERE invite_code=$1 AND NOT is_group', [code])).rows[0];
    if (!s) return { error: 'That invite code is not valid.' };
    if (await isMember(me, s.id)) return { error: 'You are already in that server.' };
    await pool.query('INSERT INTO server_members (server_id, user_id) VALUES ($1,$2)', [s.id, me]);
    io.in('u:' + me).socketsJoin('s:' + s.id);
    io.to('u:' + me).emit('server:added', { server: s });
    io.to('s:' + s.id).emit('member:joined', { serverId: s.id, member: { id: me, username: myName, online: true, av: await getAv(me) } });
    return { ok: true, serverId: s.id };
  });

  on('channel:create', async ({ serverId, name }) => {
    serverId = Number(serverId);
    const s = (await pool.query('SELECT owner_id FROM servers WHERE id=$1', [serverId])).rows[0];
    if (!s || s.owner_id !== me) return { error: 'Only the server owner can add channels.' };
    name = String(name || '').trim().toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9_-]/g, '').slice(0, 30);
    if (!name) return { error: 'Use letters, numbers, dashes or underscores.' };
    try {
      const { rows } = await pool.query('INSERT INTO channels (server_id, name) VALUES ($1,$2) RETURNING id, name', [serverId, name]);
      io.to('s:' + serverId).emit('channel:added', { serverId, channel: rows[0] });
    } catch (e) {
      if (e.code === '23505') return { error: 'A channel with that name already exists.' };
      throw e;
    }
  });

  on('channel:message', async ({ channelId, content, replyTo }) => {
    channelId = Number(channelId);
    content = typeof content === 'string' ? content.trim() : '';
    if (!channelId || !content) return { error: 'Write a message first.' };
    if (content.length > 2000) return { error: 'Messages can be up to 2000 characters.' };
    const c = (await pool.query('SELECT server_id FROM channels WHERE id=$1', [channelId])).rows[0];
    if (!c || !(await isMember(me, c.server_id))) return { error: 'You cannot post in this channel.' };
    const rt = Number(replyTo) || null;
    if (rt && !(await pool.query('SELECT 1 FROM channel_messages WHERE id=$1 AND channel_id=$2', [rt, channelId])).rowCount)
      return { error: 'The message you are replying to no longer exists.' };
    const { rows } = await pool.query(
      'INSERT INTO channel_messages (channel_id, sender_id, content, reply_to) VALUES ($1,$2,$3,$4) RETURNING id', [channelId, me, content, rt]);
    io.to('s:' + c.server_id).emit('channel:message', { ...(await getMessage(rows[0].id)), serverId: c.server_id });
  });

  const ctxFor = async (id) => {
    const x = (await pool.query(
      `SELECT m.sender_id, m.channel_id, c.server_id, s.owner_id FROM channel_messages m
       JOIN channels c ON c.id=m.channel_id JOIN servers s ON s.id=c.server_id WHERE m.id=$1`, [Number(id) || 0])).rows[0];
    return x && (await isMember(me, x.server_id)) ? x : null;
  };
  const pushUpdate = async (id, x) => io.to('s:' + x.server_id).emit('message:updated', { message: await getMessage(id), serverId: x.server_id });

  on('message:edit', async ({ id, content }) => {
    content = typeof content === 'string' ? content.trim() : '';
    if (!content || content.length > 2000) return { error: 'Messages must be 1–2000 characters.' };
    const x = await ctxFor(id);
    if (!x || x.sender_id !== me) return { error: 'You can only edit your own messages.' };
    await pool.query('UPDATE channel_messages SET content=$1, edited_at=NOW() WHERE id=$2 AND NOT is_system', [content, Number(id)]);
    await pushUpdate(Number(id), x);
  });

  on('message:delete', async ({ id }) => {
    const x = await ctxFor(id);
    if (!x || (x.sender_id !== me && x.owner_id !== me)) return { error: 'You cannot delete this message.' };
    await pool.query('DELETE FROM channel_messages WHERE id=$1', [Number(id)]);
    io.to('s:' + x.server_id).emit('message:deleted', { id: Number(id), channelId: x.channel_id, serverId: x.server_id });
  });

  on('message:pin', async ({ id, pinned }) => {
    const x = await ctxFor(id);
    if (!x || x.owner_id !== me) return { error: 'Only the server owner can pin messages for now.' };
    await pool.query('UPDATE channel_messages SET pinned=$1 WHERE id=$2 AND NOT is_system', [!!pinned, Number(id)]);
    await pushUpdate(Number(id), x);
    if (pinned) {
      const r = await pool.query(
        "INSERT INTO channel_messages (channel_id, sender_id, content, is_system) VALUES ($1,$2,'pinned a message',TRUE) RETURNING id", [x.channel_id, me]);
      io.to('s:' + x.server_id).emit('channel:message', { ...(await getMessage(r.rows[0].id)), serverId: x.server_id });
    }
  });

  on('reaction:toggle', async ({ id, emoji }) => {
    if (typeof emoji !== 'string' || !emoji || emoji.length > 16) return { error: 'Invalid emoji.' };
    const x = await ctxFor(id);
    if (!x) return { error: 'Message not found.' };
    const del = await pool.query('DELETE FROM message_reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3', [Number(id), me, emoji]);
    if (!del.rowCount) await pool.query('INSERT INTO message_reactions (message_id, user_id, emoji) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [Number(id), me, emoji]);
    await pushUpdate(Number(id), x);
  });

  on('channel:typing', async ({ channelId, isTyping }) => {
    const sid = await chServer(Number(channelId));
    if (sid && (await isMember(me, sid)))
      socket.to('s:' + sid).emit('channel:typing', { channelId: Number(channelId), userId: me, username: myName, isTyping: !!isTyping });
  });

  on('group:create', async ({ name, memberIds }) => {
    const ids = [...new Set((Array.isArray(memberIds) ? memberIds : []).map(Number).filter((n) => n && n !== me))].slice(0, 9);
    if (!ids.length) return { error: 'Pick at least one friend.' };
    for (const id of ids) if (!(await areFriends(me, id))) return { error: 'You can only add friends to a group.' };
    name = typeof name === 'string' ? name.trim().slice(0, 30) : '';
    if (!name) name = (await pool.query('SELECT username FROM users WHERE id=ANY($1)', [[me, ...ids]])).rows.map((r) => r.username).join(', ').slice(0, 30);
    const s = (await pool.query(
      'INSERT INTO servers (name, owner_id, invite_code, is_group) VALUES ($1,$2,$3,TRUE) RETURNING id, name, owner_id, invite_code, is_group',
      [name, me, crypto.randomBytes(4).toString('hex')])).rows[0];
    for (const id of [me, ...ids]) await pool.query('INSERT INTO server_members (server_id, user_id) VALUES ($1,$2)', [s.id, id]);
    await pool.query("INSERT INTO channels (server_id, name) VALUES ($1, 'chat')", [s.id]);
    for (const id of [me, ...ids]) {
      io.in('u:' + id).socketsJoin('s:' + s.id);
      io.to('u:' + id).emit('server:added', { server: s });
    }
    return { ok: true, serverId: s.id };
  });

  on('group:add', async ({ groupId, userId }) => {
    groupId = Number(groupId); userId = Number(userId);
    const g = (await pool.query('SELECT id, name, owner_id, invite_code, is_group FROM servers WHERE id=$1', [groupId])).rows[0];
    if (!g || !g.is_group || !(await isMember(me, groupId))) return { error: 'Group not found.' };
    if (!(await areFriends(me, userId))) return { error: 'You can only add your friends.' };
    if (await isMember(userId, groupId)) return { error: 'They are already in this group.' };
    if ((await pool.query('SELECT COUNT(*)::int AS n FROM server_members WHERE server_id=$1', [groupId])).rows[0].n >= 10)
      return { error: 'Groups can have up to 10 members.' };
    await pool.query('INSERT INTO server_members (server_id, user_id) VALUES ($1,$2)', [groupId, userId]);
    const u = (await pool.query('SELECT id, username, avatar_v AS av FROM users WHERE id=$1', [userId])).rows[0];
    io.in('u:' + userId).socketsJoin('s:' + groupId);
    io.to('u:' + userId).emit('server:added', { server: g });
    io.to('s:' + groupId).emit('member:joined', { serverId: groupId, member: { ...u, online: isOnline(userId) } });
  });

  on('group:kick', async ({ groupId, userId }) => {
    groupId = Number(groupId); userId = Number(userId);
    const g = (await pool.query('SELECT owner_id, is_group FROM servers WHERE id=$1', [groupId])).rows[0];
    if (!g || !g.is_group || g.owner_id !== me) return { error: 'Only the group owner can remove members.' };
    if (userId === me) return { error: 'Use Leave group instead.' };
    const del = await pool.query('DELETE FROM server_members WHERE server_id=$1 AND user_id=$2', [groupId, userId]);
    if (!del.rowCount) return { error: 'That person is not in the group.' };
    io.to('u:' + userId).emit('server:removed', { serverId: groupId, kicked: true });
    io.in('u:' + userId).socketsLeave('s:' + groupId);
    io.to('s:' + groupId).emit('member:left', { serverId: groupId, userId });
  });

  on('user:block', async ({ userId }) => {
    userId = Number(userId);
    if (!userId || userId === me) return { error: 'Invalid user.' };
    if (!(await pool.query('SELECT 1 FROM users WHERE id=$1', [userId])).rowCount) return { error: 'User not found.' };
    await pool.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [me, userId]);
    await pool.query('DELETE FROM friendships WHERE (requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1)', [me, userId]);
    io.to('u:' + me).emit('friend:removed', { userId });
    io.to('u:' + userId).emit('friend:removed', { userId: me });
  });

  on('user:unblock', async ({ userId }) => {
    await pool.query('DELETE FROM blocks WHERE blocker_id=$1 AND blocked_id=$2', [me, Number(userId)]);
    io.to('u:' + me).emit('block:removed', { userId: Number(userId) });
  });

  on('server:leave', async ({ serverId }) => {
    serverId = Number(serverId);
    const s = (await pool.query('SELECT owner_id, is_group FROM servers WHERE id=$1', [serverId])).rows[0];
    if (!s || !(await isMember(me, serverId))) return { error: 'You are not in that server.' };
    if (s.is_group && s.owner_id === me) {
      const nx = (await pool.query('SELECT user_id FROM server_members WHERE server_id=$1 AND user_id<>$2 ORDER BY joined_at LIMIT 1', [serverId, me])).rows[0];
      if (nx) {
        await pool.query('UPDATE servers SET owner_id=$1 WHERE id=$2', [nx.user_id, serverId]);
        s.owner_id = nx.user_id;
        io.to('s:' + serverId).emit('group:owner', { serverId, ownerId: nx.user_id });
      }
    }
    if (s.owner_id === me) {
      await pool.query('DELETE FROM servers WHERE id=$1', [serverId]);
      io.to('s:' + serverId).emit('server:removed', { serverId, deleted: true });
      io.in('s:' + serverId).socketsLeave('s:' + serverId);
    } else {
      await pool.query('DELETE FROM server_members WHERE server_id=$1 AND user_id=$2', [serverId, me]);
      io.to('u:' + me).emit('server:removed', { serverId });
      io.in('u:' + me).socketsLeave('s:' + serverId);
      io.to('s:' + serverId).emit('member:left', { serverId, userId: me });
    }
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
