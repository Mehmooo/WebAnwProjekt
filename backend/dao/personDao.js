const helper = require('../helper.js');
const BenutzerDao = require('./benutzerDao.js');
const AdresseDao = require('./adresseDao.js');
const BestellungDao = require('./bestellungDao.js');

class PersonDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }
}

module.exports = PersonDao;