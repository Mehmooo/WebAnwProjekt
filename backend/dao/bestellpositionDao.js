const helper = require('../helper.js');
const ProduktDao = require('./produktDao.js');

class BestellpositionDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }
}

module.exports = BestellpositionDao;