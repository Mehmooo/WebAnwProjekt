const helper = require('../helper.js');
const ProduktDao = require('./produktDao.js');


class VarianteDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

    loadAllVariants(id) {
        var sql = 'SELECT id FROM Produkt_Variante WHERE produktId=?';
        var statement = this._conn.prepare(sql);
        var result = statement.all();

        if (helper.isUndefined(result))
            throw new Error('Keine Ressourceneinträge zu Varianten gefunden');

        return result;
    }
}


module.exports = VarianteDao;