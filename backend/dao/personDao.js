const helper = require('../helper.js');
const BenutzerDao = require('./benutzerDao.js');
const AdresseDao = require('./adresseDao.js');

class PersonDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }
}

module.exports = PersonDao;