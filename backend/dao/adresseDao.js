const helper = require("../helper.js");

class AdresseDao {
  constructor(dbConnection) {
    this._conn = dbConnection;
  }

  getConnection() {
    return this._conn;
  }

  setadresse(city, postcode, street, number) {
    var sql =
      "INSERT INTO Adresse (street, number, postcode, city) VALUES (?, ?, ?, ?)";
    var statement = this._conn.prepare(sql);
    var result = statement.run(street, number, postcode, city);
    if (helper.isUndefined(result))
      throw new Error("Benutzer konnte nicht registriert werden");
    return result;
  }
}

module.exports = AdresseDao;
