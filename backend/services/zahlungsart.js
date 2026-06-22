const helper = require('../helper.js');
const ZahlungsartDao = require('../dao/zahlungsartDao.js');
const express = require('express');
var serviceRouter = express.Router();

console.log(' Service Zahlungsart ');

serviceRouter.get('/loadAllPaymentMethods', function(request, response) {
    const zahlungsartDao = new ZahlungsartDao(request.app.locals.dbConnection);
    try {
        var obj = zahlungsartDao.loadAllPaymentMethods();
        response.status(200).json(obj);
    } catch (ex) {
        response.status(400).json({
            'fehler': true,
            'nachricht': ex.message
        });
    }
});

module.exports = serviceRouter;
