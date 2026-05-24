const helper = require('../helper.js');


class ZahlungsartDao {
    constructor(dbConnection) {
        this._conn = dbConnection
    }

    getConnection() {
        return this._conn;
    }

    loadAllPaymentMethods() {
        var sql = 'SELECT * FROM Zahlungsart';
        var statement = this._conn.prepare(sql);
        var result = statement.all();

        if (helper.isUndefined(result))
            throw new Error('Keine Ressourceneinträge bei Zahlungsarten gefunden');

        return result;
    }

    loadById(id) {
        var sql = 'SELECT * FROM Zahlungsart WHERE id=?';
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if (helper.isUndefined(result)) {
            throw new Error('No Record by id=' + id);
        }

        return result;
    }
}

module.exports = ZahlungsartDao;