const helper = require('../helper.js');
const ProduktDao = require('../dao/produktDao.js');
const express = require('express');
var serviceRouter = express.Router();

console.log('Service Produkt');

serviceRouter.get('/loadAllProducts', function(request, response) {
    const produktDao = new ProduktDao(request.app.locals.dbConnection);
    try {
        var obj = produktDao.loadAllProducts();
        response.status(200).json(obj);
    } catch (ex) {
        response.status(400).json({
            'fehler': true,
            'nachricht': ex.message
        });
    }
});

module.exports = serviceRouter;