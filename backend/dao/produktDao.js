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
        const produktBild = new ProduktbildDao(this._conn);
        var sql = 'SELECT id, bezeichnung, preis FROM Produkt';
        var statement = this._conn.prepare(sql);
        var result = statement.all();

        if (helper.isUndefined(result))
            throw new Error('Keine Ressourceneinträge bei Produkte gefunden');

        for (let i = 0; i<result.length; i++) {
            result[i].bildpfad = produktBild.loadById(result[i].id);
        }

        return result;
    }

    loadProductById(id) {
        const produktBild = new ProduktbildDao(this._conn);
        var sql = 'SELECT * FROM Produkt WHERE id=?';
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if (helper.isUndefined(result))
            throw new Error('Keine Ressourceneintrag zur Produkt ID = ' + id + ' gefunden');
        
        result.bildpfad = produktBild.loadById(result.id);
        return result;
    }
}

module.exports = ProduktDao;