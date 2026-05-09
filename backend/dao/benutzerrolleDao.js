const helper = require('../helper.js');


class BenutzerrolleDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

}

module.exports = BenutzerrolleDao;