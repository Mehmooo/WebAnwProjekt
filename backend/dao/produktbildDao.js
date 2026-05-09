const helper = require('../helper.js');

class ProduktbildDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

}

module.exports = ProduktbildDao;