const helper = require('../helper.js');
const ProduktbildDao = require('../dao/produktbildDao.js');
const express = require('express');
var serviceRouter = express.Router();

console.log(' Service Produktbild ');

serviceRouter.get('loadPicture/:id', function(request, response) {
    const produktbildDao = new ProduktbildDao(request.app.locals.dbConnection);

    try {
        var obj = produktbildDao.loadById(request.body.id);
        response.status(200).json(obj);
    } catch (ex) {
        console.log('Service Produktbild: Fehler beim Laden der Ressource. Fehler Nachricht: ' + ex.message);
        response.status(400).json({
            'fehler': true,
            'nachricht': ex.message
        });
    }
})




module.exports = serviceRouter;