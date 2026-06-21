const helper = require('../helper.js');
const BestellungDao = require('../dao/bestellungDao.js');
const express = require('express');
var serviceRouter = express.Router();

console.log(' Service Bestellung ');

serviceRouter.post('/newOrder', function(request, response) {
    
    
    var errorMsgs=[];
    if (helper.isUndefined(request.body.bestellzeitpunkt)) {
        request.body.bestellzeitpunkt = helper.getNow();
    } else if(!helper.isGermanDateTimeFormat(request.body.bestellzeitpunkt)) {
        errorMsgs.push('Bestellzeitpunkt hat das falsche Format, erlaubt: dd.mm.jjjj hh.mm.ss');
    } else {
        request.body.bestellzeitpunkt = helper.parseGermanDateTimeString(request.body.bestellzeitpunkt);
    }

    if (helper.isUndefined(request.body.besteller)) {
        request.body.besteller = null
    } else if (helper.isUndefined(request.body.besteller.id)) {
        errorMsgs.push('Besteller gesetzt, aber Id fehlt');
    } 
    //else {
    //    request.body.besteller = request.body.besteller.id;
    //}

    if (helper.isUndefined(request.body.zahlungsart)) {
        errorMsgs.push('Zahlungart fehlt');
    } else if (helper.isUndefined(request.body.zahlungsart.id)) {
        errorMsgs.push('Zahlungsart gesetzt, aber id fehlt');
    }

    if (helper.isUndefined(request.body.bestellpositionen)) {
        errorMsgs.push('Bestellpositionen fehlen');
    } else if (!helper.isArray(request.body.bestellpositionen)) {
        errorMsgs.push('Bestellpositionen ist kein Array');
    } else if (request.body.bestellpositionen.length == 0) {
        errorMsgs.push('Bestellpositionen ist leer, nichts zu speichern');
    }

    if (errorMsgs.length > 0) {
        console.log('Service Bestellung: Creation not possible, data missing');
        response.status(400).json({
            'fehler': true,
            'nachricht': 'Funktion nicht möglich. Fehlende Daten: ' + helper.concatArray(errorMsgs)
        
        });
    }

    console.log("Ich bin jetzt im Service bei NEW ORDER DRINNE");
    console.log('Service Bestellung: Client requested creation of new Record');
    console.log("IM ENDPUNKT NEWORDER DER BODY: ", request);

    const bestellungDao = new BestellungDao(request.app.locals.dbConnection);
    try {
        console.log("BEVOR DER BESTELLUNGDAO CREATE AUFGERUFEN WIRD");
        console.log("Das ist die Request Body: ", request.body);
        var obj = bestellungDao.create(request.body.bestellzeitpunkt, parseInt(request.body.besteller.id), request.body.zahlungsart.id, request.body.bestellpositionen);
        console.log('Service Bestellung: Record inserted');
        response.status(200).json(obj);
    } catch (ex) {
        console.error('Service Bestellung: Error creating new record. Exception occured: ' + ex.message);
        response.status(400).json({
            'fehler': true,
            'nachricht': ex.message
        });
    }
});

module.exports = serviceRouter;