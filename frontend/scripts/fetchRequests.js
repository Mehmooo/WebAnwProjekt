const apiMain = 'http://localhost:8000/api';

async function loadPicturesHomepage(endpoint) {
    var apiFetch = apiMain + endpoint; // To build the API URL to the endpoint
    console.log("The API Fetch URL" + apiFetch);

    try {
        const response = await fetch(apiFetch); //Call the Get Routes in the service produktbild.js
        const data = await response.json();

        if (response.status === 200) {
            console.log("Status Erfolgreich")
            return data;
        } else {
            console.log("Fehlgeschlagen siehe Status Code " + data.status);
            return data;
        }
    } catch (error) {
        console.log(error);
    }
}

async function loadAllProductsInOverview(endpoint) {
    console.log("Jetzt auf PRODUKTSÜBERSICHTSEITE");
    var apiFetch = apiMain + endpoint;
    console.log("The API Fetch URL" + apiFetch);
    var mainImagePfad = '/images/';

    try {
        const response = await fetch(apiFetch);
        const data = await response.json();

        if (response.status === 200) {
            console.log('Status Successful, now the new API Call for loadPicture')
            var divParent = document.querySelector('.products_overview_grid');
            for (let i = 0; i < data.length; i++) {
                console.log("In der for loop");
                let a = document.createElement('a');
                let div = document.createElement('div');
                let img = document.createElement('img');
                let p = document.createElement('p');
                a.classList.add('product-card');
                a.href = `product_detail.html?id=${data[i].id}`;
                div.classList.add('products_square');
                img.src = data[i].bildpfad.bildpfad;
                console.log("Bildpfad ", data[i].bildpfad.bildpfad);
                img.alt = 'DEFAULT';
                p.innerHTML = `${data[i].bezeichnung}<br>${data[i].preis} €`;
                divParent.appendChild(a);
                a.appendChild(div);
                div.appendChild(img);
                div.appendChild(p);
            }
        } else {
            console.log('Status Unsuccessful look at this status Code ' + data.status);
            return data;
        }
        
        
    } catch (error) {
        console.log(error);
    }

    console.log("ALLE PRODUKTE IN OVERVIEW GELADEN");

}

async function loadProductDetail() {
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    console.log("DIE ID IST VON DIESER SEITE: ", id);
    var apiFetch = apiMain + '/loadProduct/' + id.toString();
    console.log("DER API FETCH: ", apiFetch);
    try {
        const response = await fetch(apiFetch);
        const data = await response.json();
        const title = document.querySelector('#productTitle');
        const price = document.querySelector('#productPrice');
        const descr = document.querySelector('#productDescr');
        title.textContent = data.bezeichnung;
        price.textContent = data.preis + '€';
        descr.textContent = data.beschreibung;
        //Call for Picture load
        //const responsePictureData = await loadPicturesHomepage('/loadPicture', id);
        console.log('Antwort von Detail Bild: ' + data.bildpfad.bildpfad);
        const pictureDetail = document.querySelector('#pictureDetailSite');
        pictureDetail.src = data.bildpfad.bildpfad;
        
        pictureDetail.alt = 'DEFAULT';
        //await loadVariants();
    } catch (error) {
        console.log(error);
    }
    console.log("DETAILSEITE FERTIG GELADEN");
    
}

async function loadAllPaymentMethods(endpoint) {
    const apiFetch = apiMain + endpoint;
    const response = await fetch(apiFetch);
    const data = await response.json();
    return data;

}

async function closeOrder(endpoint, paymentId, session) {
    const apiFetch = apiMain + endpoint;
    console.log("DER API FETCH: ", apiFetch);
    const response = await fetch(apiFetch, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'besteller': {
                'id': 1
            },
            'zahlungsart': {
                'id': paymentId
            },
            'bestellpositionen' : session 
        })
    });
    const data = response.json();
    return data;
}