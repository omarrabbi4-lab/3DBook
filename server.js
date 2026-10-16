
const express = require("express");
const http = require("http");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const GROUP_INVITE_CODE = process.env.GROUP_INVITE_CODE;

if (!DATABASE_URL) throw new Error("DATABASE_URL missing");
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters");
}
if (!GROUP_INVITE_CODE || GROUP_INVITE_CODE.length < 6) {
  throw new Error("GROUP_INVITE_CODE must be at least 6 characters");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true"
    ? { rejectUnauthorized: false }
    : undefined
});

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 90,
  standardHeaders: true,
  legacyHeaders: false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      phone VARCHAR(20) UNIQUE NOT NULL,
      display_name VARCHAR(40) NOT NULL,
      pin_hash TEXT NOT NULL,
      role VARCHAR(10) NOT NULL DEFAULT 'member',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      kind VARCHAR(12) NOT NULL DEFAULT 'text',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS messages_created_at_idx
      ON messages(created_at DESC);

    CREATE TABLE IF NOT EXISTS message_reactions (
      message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      emoji VARCHAR(8) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(message_id, user_id, emoji)
    );
  `);
}

function normalizePhone(value) {
  let phone = String(value || "").replace(/[^\d+]/g, "");

  if (phone.startsWith("+880")) phone = "0" + phone.slice(4);
  else if (phone.startsWith("880")) phone = "0" + phone.slice(3);

  return phone;
}

function publicUser(row) {
  return {
    id: String(row.id),
    phone: row.phone,
    name: row.display_name,
    role: row.role
  };
}

function makeToken(row) {
  return jwt.sign(
    { id: String(row.id) },
    JWT_SECRET,
    { expiresIn: "14d", issuer: "bondhu-mohol" }
  );
}

async function authFromToken(token) {
  const payload = jwt.verify(token, JWT_SECRET, {
    issuer: "bondhu-mohol"
  });

  const result = await pool.query(
    "SELECT id, phone, display_name, role FROM users WHERE id=$1",
    [payload.id]
  );

  if (!result.rowCount) throw new Error("User not found");
  return publicUser(result.rows[0]);
}

async function requireAuth(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");

    if (!token) {
      return res.status(401).json({ error: "আগে লগইন করুন।" });
    }

    req.user = await authFromToken(token);
    next();
  } catch {
    res.status(401).json({
      error: "লগইনের মেয়াদ শেষ। আবার লগইন করুন।"
    });
  }
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, app: "Bondhu Mohol" });
  } catch {
    res.status(503).json({ ok: false, error: "Database unavailable" });
  }
});

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const name = String(req.body.name || "")
      .trim().replace(/\s+/g, " ");
    const pin = String(req.body.pin || "");
    const invite = String(req.body.invite || "");

    if (!/^01[3-9]\d{8}$/.test(phone)) {
      return res.status(400).json({
        error: "সঠিক ১১ সংখ্যার বাংলাদেশি মোবাইল নম্বর দিন।"
      });
    }

    if (name.length < 2 || name.length > 40) {
      return res.status(400).json({
        error: "নাম ২–৪০ অক্ষরের মধ্যে দিন।"
      });
    }

    if (!/^\d{6,8}$/.test(pin)) {
      return res.status(400).json({
        error: "৬–৮ সংখ্যার PIN দিন।"
      });
    }

    if (invite !== GROUP_INVITE_CODE) {
      return res.status(403).json({
        error: "আমন্ত্রণ কোড সঠিক নয়।"
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE phone=$1",
      [phone]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        error: "এই নম্বরে অ্যাকাউন্ট আছে। লগইন করুন।"
      });
    }

    // প্রথম অ্যাকাউন্ট অ্যাডমিন; সর্বোচ্চ ১০টি অ্যাকাউন্ট।
    const count = await pool.query(
      "SELECT COUNT(*)::int AS total FROM users"
    );

    if (count.rows[0].total >= 10) {
      return res.status(403).json({
        error: "১০ জন সদস্য পূর্ণ হয়েছে।"
      });
    }

    const role = count.rows[0].total === 0 ? "admin" : "member";
    const pinHash = await bcrypt.hash(pin, 12);

    const result = await pool.query(
      `INSERT INTO users(phone, display_name, pin_hash, role)
       VALUES($1, $2, $3, $4)
       RETURNING id, phone, display_name, role`,
      [phone, name, pinHash, role]
    );

    res.status(201).json({
      token: makeToken(result.rows[0]),
      user: publicUser(result.rows[0])
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        error: "এই মোবাইল নম্বরে অ্যাকাউন্ট আছে।"
      });
    }

    console.error("Register error:", err.message);
    res.status(500).json({ error: "রেজিস্ট্রেশন করা যায়নি।" });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const pin = String(req.body.pin || "");

    if (!/^01[3-9]\d{8}$/.test(phone) || !/^\d{6,8}$/.test(pin)) {
      return res.status(400).json({
        error: "মোবাইল নম্বর ও ৬–৮ সংখ্যার PIN দিন।"
      });
    }

    const result = await pool.query(
      `SELECT id, phone, display_name, pin_hash, role
       FROM users WHERE phone=$1`,
      [phone]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(pin, result.rows[0].pin_hash))
    ) {
      return res.status(401).json({
        error: "মোবাইল নম্বর অথবা PIN সঠিক নয়।"
      });
    }

    res.json({
      token: makeToken(result.rows[0]),
      user: publicUser(result.rows[0])
    });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "লগইন করা যায়নি।" });
  }
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/members", requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT id, phone, display_name, role, created_at
     FROM users ORDER BY created_at ASC`
  );

  res.json({ members: result.rows.map(publicUser) });
});

app.get("/api/messages", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.id, m.user_id, u.display_name AS name, u.role,
              m.body, m.kind, m.created_at,
              COALESCE((
                SELECT json_agg(json_build_object(
                  'emoji', r.emoji,
                  'count', r.cnt,
                  'mine', r.mine
                ))
                FROM (
                  SELECT emoji, COUNT(*)::int AS cnt,
                         BOOL_OR(user_id=$1) AS mine
                  FROM message_reactions
                  WHERE message_id=m.id
                  GROUP BY emoji
                ) r
              ), '[]'::json) AS reactions
       FROM (
         SELECT * FROM messages
         ORDER BY id DESC LIMIT 100
       ) m
       JOIN users u ON u.id=m.user_id
       ORDER BY m.id ASC`,
      [req.user.id]
    );

    res.json({
      messages: result.rows.map(r => ({
        ...r,
        id: String(r.id),
        user_id: String(r.user_id)
      }))
    });
  } catch (err) {
    console.error("Messages error:", err.message);
    res.status(500).json({ error: "মেসেজ লোড করা যায়নি।" });
  }
});

app.post("/api/messages", requireAuth, messageLimiter, async (req, res) => {
  try {
    let body = String(req.body.body || "").trim();
    let kind = "text";

    if (req.body.kind === "image") {
      try {
        const url = new URL(body);
        if (!["https:", "http:"].includes(url.protocol)) throw new Error();
        body = url.toString();
        kind = "image";
      } catch {
        return res.status(400).json({
          error: "সঠিক ছবি-লিংক দিন।"
        });
      }
    }

    if (!body || body.length > 2000) {
      return res.status(400).json({
        error: "মেসেজ ১–২০০০ অক্ষরের মধ্যে হতে হবে।"
      });
    }

    const result = await pool.query(
      `INSERT INTO messages(user_id, body, kind)
       VALUES($1, $2, $3)
       RETURNING id, user_id, body, kind, created_at`,
      [req.user.id, body, kind]
    );

    const message = {
      ...result.rows[0],
      id: String(result.rows[0].id),
      user_id: String(result.rows[0].user_id),
      name: req.user.name,
      role: req.user.role,
      reactions: []
    };

    io.emit("new-message", message);
    res.status(201).json({ message });
  } catch (err) {
    console.error("Send message error:", err.message);
    res.status(500).json({ error: "মেসেজ পাঠানো যায়নি।" });
  }
});

app.delete("/api/messages/:id", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM messages WHERE id=$1 AND user_id=$2 RETURNING id",
      [req.params.id, req.user.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "মেসেজ পাওয়া যায়নি অথবা এটি তোমার নয়।"
      });
    }

    io.emit("message-deleted", { id: String(req.params.id) });
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "মেসেজ মুছতে পারিনি।" });
  }
});

app.post("/api/messages/:id/reactions", requireAuth, async (req, res) => {
  const allowed = ["😂", "❤️", "🔥", "👍", "😎", "😭", "🤣", "🎉"];
  const emoji = String(req.body.emoji || "");

  if (!allowed.includes(emoji)) {
    return res.status(400).json({ error: "রিঅ্যাকশন অনুমোদিত নয়।" });
  }

  try {
    const exists = await pool.query(
      "SELECT id FROM messages WHERE id=$1",
      [req.params.id]
    );

    if (!exists.rowCount) {
      return res.status(404).json({ error: "মেসেজ পাওয়া যায়নি।" });
    }

    const found = await pool.query(
      `SELECT 1 FROM message_reactions
       WHERE message_id=$1 AND user_id=$2 AND emoji=$3`,
      [req.params.id, req.user.id, emoji]
    );

    if (found.rowCount) {
      await pool.query(
        `DELETE FROM message_reactions
         WHERE message_id=$1 AND user_id=$2 AND emoji=$3`,
        [req.params.id, req.user.id, emoji]
      );
    } else {
      await pool.query(
        `INSERT INTO message_reactions(message_id,user_id,emoji)
         VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
        [req.params.id, req.user.id, emoji]
      );
    }

    const reactions = await pool.query(
      `SELECT emoji, COUNT(*)::int AS count,
              BOOL_OR(user_id=$2) AS mine
       FROM message_reactions
       WHERE message_id=$1 GROUP BY emoji`,
      [req.params.id, req.user.id]
    );

    const update = {
      id: String(req.params.id),
      reactions: reactions.rows
    };

    io.emit("reaction-update", update);
    res.json(update);
  } catch (err) {
    console.error("Reaction error:", err.message);
    res.status(500).json({ error: "রিঅ্যাকশন যোগ করা যায়নি।" });
  }
});

const onlineUsers = new Map();

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("লগইন প্রয়োজন"));
    socket.user = await authFromToken(token);
    next();
  } catch {
    next(new Error("লগইনের মেয়াদ শেষ"));
  }
});

io.on("connection", socket => {
  const id = socket.user.id;
  const current = onlineUsers.get(id);

  onlineUsers.set(id, {
    user: socket.user,
    sockets: (current?.sockets || 0) + 1
  });

  function emitPresence() {
    io.emit(
      "presence",
      Array.from(onlineUsers.values()).map(x => x.user)
    );
  }

  emitPresence();

  socket.on("disconnect", () => {
    const item = onlineUsers.get(id);

    if (item) {
      if (item.sockets <= 1) {
        onlineUsers.delete(id);
      } else {
        onlineUsers.set(id, {
          ...item,
          sockets: item.sockets - 1
        });
      }
    }

    emitPresence();
  });
});

// Express 5-compatible fallback route
app.get("/{*splat}", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDb().then(() => {
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`Bondhu Mohol running on port ${PORT}`);
  });
}).catch(err => {
  console.error("Database initialization failed:", err);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  server.close();
  await pool.end();
  process.exit(0);
});
