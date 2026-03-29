const fs = require("fs");
const express = require("express");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const path = require("path");
const { open } = require("sqlite");

const app = express();
app.use(cors());
app.use(express.json());

// SQLite DB (Datei im Container)
const dbDir = path.join(__dirname, "data");
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}
const dbPath = path.join(dbDir, "database.db");
const db = new sqlite3.Database(dbPath);

// Tabelle anlegen (falls nicht existiert)
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

async function initDB() {
  return open({
    filename: dbPath,
    driver: sqlite3.Database,
  });
}

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    function (err) {
      if (err) {
        if (err.code === "SQLITE_CONSTRAINT") {
          return res.status(409).json({ message: "Username already exists" });
        }
        return res.status(500).json({ message: "DB error" });
      }
      res.json({ message: "User registered successfully 🎉" });
    },
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT password FROM users WHERE username = ?",
    [username],
    async (err, row) => {
      if (err) {
        return res.status(500).json({ message: "DB error" });
      }

      if (!row) {
        return res.status(401).json({ message: "User not found ❌" });
      }

      const valid = await bcrypt.compare(password, row.password);

      if (valid) {
        res.json({ message: "Login successful 🎉" });
      } else {
        res.status(401).json({ message: "Wrong password ❌" });
      }
    },
  );
});

app.listen(3000, () => {
  console.log("Backend running on port 3000");
  console.log("Health check available on 3000/health");
  console.log("DB check available on 3000/db");
});

app.get("/health", (req, res) => {
  try {
    res.status(200).json({
      status: "ok",
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      message: err.message,
    });
  }
});

app.get("/db", async (req, res) => {
  try {
    const db = await initDB();
    const rows = await db.all("SELECT * FROM users");
    res.json({ status: "ok", data: rows });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});
