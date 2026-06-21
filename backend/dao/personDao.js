const helper = require('../helper.js');
const BenutzerDao = require('./benutzerDao.js');
const AdresseDao = require('./adresseDao.js');
//const BestellungDao = require('./bestellungDao.js');

class PersonDao {
    constructor(dbConnection) {
        this._conn = dbConnection;
    }

    getConnection() {
        return this._conn;
    }

    loadById(id) {
        const adresseDao = new AdresseDao(this._conn);

        var sql = 'SELECT * FROM Person WHERE id=?';
        var statement = this._conn.prepare(sql);
        var result = statement.get(id);

        if (helper.isUndefined(result))
            throw new Error('No Record found by id=' + id);

        if (result.anrede == 0) {
            result.andrede = 'Herr';
        } else {
            result.anrede = 'Frau';
        }

        result.geburtstag = helper.formatToGermanDate(helper.parseSQLDateTimeString(result.geburtstag));

        result.adresse = adresseDao.loadById(result.adresseId);
        delete result.adresseId;

        return result;
    }
}

module.exports = PersonDao;