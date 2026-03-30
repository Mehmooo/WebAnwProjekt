/*
Author: Fabian Mattes
Date: 23.03.2026

Backend for the login and register system.

main functions:
- /register: for registering a new user.
- /login: for logging in an existing user.
- /health: for checking the health of the backend.
- /db: for checking the database connection and retrieving all users.

*/

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

// ensure the data directory exists and initialize the database
const dbDir = path.join(__dirname, "data");
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}
const dbPath = path.join(dbDir, "database.db");
const db = new sqlite3.Database(dbPath);

// create users table if it doesn't exist
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

// helper function to initialize the database connection
async function initDB() {
  return open({
    filename: dbPath,
    driver: sqlite3.Database,
  });
}

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  // this function is for registrating a new user.
  // Parameters:
  //  req: the request object, containing the username and password in the body.
  //
  // Response:
  //  res: the response object, used to send back the result of the registration.
  //
  // Authors: Fabian Mattes
  // Date: 23.03.2026

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

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  // this function is for logging in an existing user.
  // Parameters:
  //  req: the request object, containing the username and password in the body.
  //
  // Response:
  //  res: the response object, used to send back the result of the login.
  //
  // Authors: Fabian Mattes
  // Date: 23.03.2026

  db.get(
    "SELECT password FROM users WHERE username = ?",
    [username],
    async (err, row) => {
      if (err) {
        return res.status(500).json({ message: "DB error" });
      }

      if (!row || !(await bcrypt.compare(password, row.password))) {
        return res
          .status(401)
          .json({ message: "Invalid username or password ❌" });
      } else {
        return res.json({ message: "Login successful 🎉" });
      }
    },
  );
});

app.listen(3000, () => {
  // dumb, because everyone can see the logs in the console.
  //just using for information purposes.
  console.log("Backend running on port 3000");
  console.log("Health check available on 3000/health");
  console.log("DB check available on 3000/db");
});

app.get("/health", (req, res) => {
  // this function is for checking the health of the backend.
  // Parameters:
  //  req: the request object, not used in this function.
  //
  // Response:
  //  res: the response object, used to send back the health status of the backend.
  //
  // Authors: Fabian Mattes
  // Date: 23.03.2026

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
  // this function is for checking the database connection and retrieving all users.
  // Parameters:
  //  req: the request object, not used in this function.
  //
  // Response:
  //  res: the response object, used to send back the status of the database connection and the list of users.
  //
  // Authors: Fabian Mattes
  // Date: 23.03.2026
  try {
    const db = await initDB();
    const rows = await db.all("SELECT * FROM users");
    res.json({ status: "ok", data: rows });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});
