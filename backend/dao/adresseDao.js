const helper = require('../helper.js');


class AdresseDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }
}

module.exports = AdresseDao;