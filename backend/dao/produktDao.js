const helper = require('../helper.js');
const ProduktbildDao = require('./produktbildDao.js');

class ProduktDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }
}

module.exports = ProduktDao;