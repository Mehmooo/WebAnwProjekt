const fs = require("fs");
const Database = require("better-sqlite3");

//const db = new Database("./db/database.db");
const db = new Database("./backend/db/database.db");

//SQL-Dateien lesen
const schema = fs.readFileSync("./backend/db/schema.sql", "utf8");
const seed = fs.readFileSync("./backend/db/seed.sql", "utf8");

//SQL ausführen
db.exec(schema);
db.exec(seed);


console.log("Datenbank erfolgreich erstellt");