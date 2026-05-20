const helper = require('../helper.js');

class ProduktbildDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

    loadById(id) {
        var sql = "SELECT bildpfad FROM Produktbild WHERE id=?";
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if (helper.isUndefined(result))
            throw new Error('Kein Ressourceneintrag gefunden für die id=' + id);
        
        return result;
    }

    loadByOnHomepage() {
        var sql = "SELECT bildpfad FROM Produktbild WHERE on_homepage=true";
        var statement = this._conn.prepare(sql);
        var result = statement.all();

        if (helper.isUndefined(result))
            throw new Error('Kein Ressourceneintraege gefunden');

        return result;
    }

}

module.exports = ProduktbildDao;