const fs = require("fs");
const Database = require("better-sqlite3");

const db = new Database("database.db");

//SQL-Dateien lesen
const chema = fs.readFileSync("schema.sql", "utf8");
const seed = fs.readFileSync("seed.sql", "utf8");

//SQL ausführen
db.exec(schema);
db.exec(seed);


console.log("Datenbank erfolgreich erstellt");