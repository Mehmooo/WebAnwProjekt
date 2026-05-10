const helper = require('../helper.js');
const ProduktbildDao = require('./produktbildDao.js');

class ProduktDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

    loadAllProducts() {
        var sql = 'SELECT id, bezeichnung, preis FROM Produkt';
        var statement = this._conn.prepare(sql);
        var result = statement.all();

        if (helper.isUndefined(result))
            throw new Error('Keine Ressourceneinträge bei Produkte gefunden');

        return result;
    }
}

module.exports = ProduktDao;