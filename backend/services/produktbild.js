const helper = require('../helper.js');
const ProduktbildDao = require('../dao/produktbildDao.js');
const express = require('express');
var serviceRouter = express.Router();

console.log(' Service Produktbild ');

serviceRouter.get('/loadPicture/:id', function(request, response) {
    const produktbildDao = new ProduktbildDao(request.app.locals.dbConnection);

    try {
        var obj = produktbildDao.loadById(request.params.id); //Call Function in the DAO
        response.status(200).json(obj);
    } catch (ex) {
        response.status(400).json({
            'fehler': true,
            'nachricht': ex.message
        });
    }
});

serviceRouter.get('/loadPictureHomepage', function(request, response) {
    const produktbildDao = new ProduktbildDao(request.app.locals.dbConnection);

    try {
        var obj = produktbildDao.loadByOnHomepage();
        response.status(200).json(obj);
    } catch (ex) {
        response.status(400).json({
            'fehler': true,
            'nachricht': ex.message
        });
    }
})




module.exports = serviceRouter;