const apiMain = 'http://localhost:8000/api';

async function loadPicturesHomepage(endpoint, id) {
    var idString = id.toString();
    var apiFetch = apiMain + endpoint + '/' + idString; // To build the API URL to the endpoint
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
    var mainImagePfad = '../images/';

    try {
        const response = await fetch(apiFetch);
        const data = await response.json();

        //Continue with new API Call
        for (let i = 0; i < data.length; i++) {
            let imagePfad = await loadPicturesHomepage('/loadPicture', data[i].id);
            let loadPath = mainImagePfad + imagePfad.bildpfad;
            data[i].bildpfad = loadPath;
        }

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
                img.src = data[i].bildpfad;
                img.alt = 'DEFAULT';
                p.innerHTML = `${data[i].bezeichnung}<br>${data[i].preis} €`;
                divParent.appendChild(a);
                a.appendChild(div);
                div.appendChild(img);
                div.appendChild(p);
            }
            //var i = 0;
            //for (let box of divParent.children) {
            //    console.log("In der for loop");
            //    console.log(data[i].preis);
            //    console.log(data[i].bildpfad);
            //    let img = document.createElement('img');
            //    let p = document.createElement('p');
            //    let div = document.createElement('div');
            //    p.innerHTML = `${data[i].bezeichnung}<br>${data[i].preis} €`;
            //    img.src = data[i].bildpfad;
            //    img.alt = 'DEFAULT';
            //    div.classList.add('products_square');
            //    div.href = "product_detail.html";
            //    box.appendChild(div);
            //    div.appendChild(img);
            //    div.appendChild(p);
            //    i++;
            //}
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
    var apiFetch = apiMain + '/loadProduct/' + id.toString();

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
        const responsePictureData = await loadPicturesHomepage('/loadPicture', id);
        console.log('Antwort von Detail Bild: ' + responsePictureData);
        const pictureDetail = document.querySelector('#pictureDetailSite');
        pictureDetail.src = '../images/' + responsePictureData.bildpfad;
        pictureDetail.alt = 'DEFAULT';
        await loadVariants();
    } catch (error) {
        console.log(error);
    }
    console.log("DETAILSEITE FERTIG GELADEN");
    
}