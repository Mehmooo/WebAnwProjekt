const helper = require('../helper.js');


class VarianteDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }


    getConnection() {
        return this._conn;
    }

    loadAllVariants(id) {
        var sql = 'SELECT farbe FROM Variante WHERE id=?';
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if (helper.isUndefined(result))
            throw new Error('Keine Ressourceneintrag zu Varianten');

        return result;
    }
}

module.exports = VarianteDao;