const helper = require('../helper.js');


class ZahlungsartDao {
    constructor(dbConnection) {
        this._conn = dbConnection
    }

    getConnection() {
        return this._conn;
    }
}

module.exports = ZahlungsartDao;