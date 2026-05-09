const helper = require('../helper.js');
const BenutzerrolleDao = require('./benutzerrolleDao.js');


class BenutzerDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }


}

module.exports = BenutzerDao;