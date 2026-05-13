const helper = require('../helper.js');
const Variante_ProductDao = require('../dao/produkt_varianteDao.js');
const VarianteDao = require('../dao/varianteDao.js');
const express = require('express');
var serviceRouter = express.Router();

console.log(' Service Produkt_Variante ');

serviceRouter.get('/loadAllVariants/:id', function(request, response) {
    console.log("In der LoadAllVariantsRoute");
    const variante_productDao = new Variante_ProductDao(request.app.locals.dbConnection);
    const varianteDao = new VarianteDao(request.app.locals.dbConnection);
    try {
        var variantId = variante_productDao.loadAllVariants(request.params.id);
        for (let i = 0; variantId.length; i++) {
            var variantDescr = varianteDao.loadAllVariants(variantId[i].id);
            variantId[i].descr = variantDescr[0]; 
        }
        response.status(200).json(obj);
        return variantId;
    } catch (ex) {
        response.status(400).json({
            'fehler': true,
            'nachricht': ex.message
        });
    }
});

module.exports = serviceRouter;