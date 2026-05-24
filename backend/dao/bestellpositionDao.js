const helper = require('../helper.js');
const ProduktDao = require('./produktDao.js');

class BestellpositionDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

    loadById(id) {
        const produktDao = new ProduktDao(this._conn);

        var sql = 'SELECT * FROM Bestellposition WHERE id=?';
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if(helper.isUndefined(result))
            throw new Error('No Record found by id=' + id);

        result.bestellung = {'id': result.bestellungId};
        delete result.bestellungId;

        result.produkt = produktDao.loadById(result.produktId);
        delete result.produktId;

        return result;
    }

    loadByParent(id) {
        const produktDao = new ProduktDao(this._conn);

        var sql = 'SELECT * FROM Bestellposition WHERE bestellungId=?';
        var statement = this._conn.prepare(sql);
        var result = statement.all(bestellungId);

        if (helper.isArrayEmpty(result))
            return [];

        for (var i = 0; i < result.length; i++) {
            result[i].bestellung = {'id': result[i].bestellungId};
            delete result[i].bestellungId;

            result[i].produkt = produktDao.loadById(result[i].produktId);
            delete result[i].produktId;
        }

        return result;
    }

    create(bestellungId = 1, produktId = 1, menge = 1) {
        var sql = 'INSERT INTO Bestellposition (bestellungId,produktId,menge) VALUES (?,?,?)';
        var statement = this._conn.prepare(sql);
        var params = [bestellungId, produktId, menge];
        var result = statement.run(params);

        if (result.changes != 1) {
            throw new Error('Could not insert new Record. Data: ' + params);
        }

        return this.loadById(result.lastInsertRowid);
    }
}

module.exports = BestellpositionDao;