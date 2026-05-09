const helper = require('../helper.js');
const BestellpositionDao = require('./bestellpositionDao.js');
const ProduktDao = require('./produktDao.js');
const ProduktbildDao = require('./produktbildDao.js');

class BestellungDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }
}

module.exports = BestellungDao;