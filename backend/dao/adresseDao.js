const helper = require('../helper.js');


class AdresseDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

    loadById(id) {
        var sql = 'SELECT * FROM Adresse WHERE id=?';
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if (helper.isUndefined(result))
            throw new Error('Keine Ressourceneinträge zu dieser AdressId gefunden');

        return result;
    }
}

module.exports = AdresseDao;