const helper = require("../helper.js");

class AuthDao {
  constructor(dbConnection) {
    this._conn = dbConnection;
  }

  getConnection() {
    return this._conn;
  }

  register(username, password) {
    var sql = "INSERT INTO Benutzer (benutzername, passwort) VALUES (?, ?)";
    var statement = this._conn.prepare(sql);
    var result = statement.run(username, password);
    if (helper.isUndefined(result))
      throw new Error("Benutzer konnte nicht registriert werden");
    return result;
  }
  exists(username) {
    var sql = "SELECT * FROM Benutzer WHERE benutzername=?";
    var statement = this._conn.prepare(sql);
    var result = statement.get(username);
    return !!result;
  }
  findByUsername(username) {
    var sql = "SELECT * FROM Benutzer WHERE benutzername=?";
    var statement = this._conn.prepare(sql);
    var result = statement.get(username);
    if (!result) {
      console.log("Benutzer nicht gefunden: ", username);
      throw new Error("Benutzer nicht gefunden");
    }
    return result;
  }
}

module.exports = AuthDao;
