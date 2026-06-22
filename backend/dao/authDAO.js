const helper = require("../helper.js");

class AuthDao {
  constructor(dbConnection) {
    this._conn = dbConnection;
  }

  getConnection() {
    return this._conn;
  }

  register(username, password, firstname, lastname, adresse) {
    var sql =
      "INSERT INTO Benutzer (benutzername, passwort, benuitzerrolleId, PersonId) VALUES (?, ?, ?, ?)";
    var statement = this._conn.prepare(sql);
    var result = statement.run(username, password, 2);
    if (helper.isUndefined(result))
      throw new Error("Benutzer konnte nicht registriert werden");
    return result;
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
