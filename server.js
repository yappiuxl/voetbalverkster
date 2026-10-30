const express = require("express");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// === БАЗА ДАННЫХ ===
const db = new Database("database.sqlite");
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    balance REAL DEFAULT 0,
    collection_value REAL DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

// === РЕГИСТРАЦИЯ ===
app.post("/api/register", async (req, res) => {
  try {
    const { nickname, password } = req.body;
    if (!nickname || !password) return res.status(400).json({ error: "Введи ник и пароль" });
    if (nickname.length < 3 || nickname.length > 20) return res.status(400).json({ error: "Ник 3-20 символов" });
    if (password.length < 3) return res.status(400).json({ error: "Пароль минимум 3 символа" });

    const existing = db.prepare("SELECT id FROM users WHERE nickname = ?").get(nickname);
    if (existing) return res.status(400).json({ error: "Такой ник уже занят" });

    const hash = await bcrypt.hash(password, 10);
    const result = db.prepare("INSERT INTO users (nickname, password_hash) VALUES (?, ?)").run(nickname, hash);

    res.json({
      ok: true,
      user: { id: result.lastInsertRowid, nickname, balance: 0, collection_value: 0 }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// === ВХОД ===
app.post("/api/login", async (req, res) => {
  try {
    const { nickname, password } = req.body;
    if (!nickname || !password) return res.status(400).json({ error: "Введи ник и пароль" });

    const user = db.prepare("SELECT * FROM users WHERE nickname = ?").get(nickname);
    if (!user) return res.status(400).json({ error: "Неверный ник или пароль" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: "Неверный ник или пароль" });

    res.json({
      ok: true,
      user: {
        id: user.id,
        nickname: user.nickname,
        balance: user.balance,
        collection_value: user.collection_value
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// === СОХРАНЕНИЕ ПРОГРЕССА ===
app.post("/api/save", (req, res) => {
  try {
    const { nickname, balance, collection_value } = req.body;
    if (!nickname) return res.status(400).json({ error: "Нет ника" });

    db.prepare("UPDATE users SET balance = ?, collection_value = ? WHERE nickname = ?")
      .run(balance || 0, collection_value || 0, nickname);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// === ТАБЛИЦА ЛИДЕРОВ ===
app.get("/api/leaderboard", (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT nickname, balance, collection_value, (balance + collection_value) AS total
      FROM users
      ORDER BY total DESC
      LIMIT 100
    `).all();

    res.json({ ok: true, leaderboard: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// === ЗАПУСК ===
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
