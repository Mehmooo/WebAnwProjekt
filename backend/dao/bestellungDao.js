const helper = require('../helper.js');
const BestellpositionDao = require('./bestellpositionDao.js');
const ProduktDao = require('./produktDao.js');
const ProduktbildDao = require('./produktbildDao.js');
const PersonDao = require('./personDao.js');

class BestellungDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

    loadById(id) {
        const bestellpositionDao = new BestellpositionDao(this._conn);
        const personDao = new PersonDao(this._conn);
        const zahlungsartDao = new ZahlungsartDao(this._conn);

        var sql = 'SELECT * FROM Bestellung WHERE id=?';
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if (helper.isUndefined(result))
            throw new Error('No Record found by Id=' + id);

        result.bestellzeitpunkt = helper.formatToGermanDateTime(helper.parseSQLDateTimeString(result.bestellzeitpunkt));

        if (helper.isNull(result.bestellerId)) {
            result.besteller = null;
        } else {
            result.besteller = personDao.loadById(result.bestellerId);
        }
        delete result.bestellerId;

        result.zahlungsart = zahlungsartDao.loadById(result.zahlungsartId);
        delete result.zahlungsartId;

        result.bestellpositionen = bestellpositionDao.loadByParent(result.id);

        return result;
    }

    create(bestellzeitpunkt = null, bestellerId = null, zahlungsartId = null, bestellpositionen = []) {
        const bestellpositionDao = new BestellpositionDao(this._conn);

        if (helper.isNull(bestellzeitpunkt))
            bestellzeitpunkt = helper.getNow();

        var sql = 'INSERT INTO Bestellung (bestellzeitpunkt,bestellerId,zahlungsartId) VALUES (?,?,?)';
        var statement = this._conn.prepare(sql);
        var params = [helper.formatToSQLDateTime(bestellzeitpunkt), bestellerId, zahlungsartId];
        var result = statement.run(params);

        if(result.changes != 1) {
            throw new Error('Could not insert new Record. Data: ' + params);
        }

        if (bestellpositionen.length > 0) {
            for (var element of bestellpositionen) {
                bestellpositionDao.create(result.lastInsertRowid, element.productId, element.amount);
            }
        }

        return this.loadById(result.lastInsertRowid);
    }
}

module.exports = BestellungDao;