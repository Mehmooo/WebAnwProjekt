const apiMain = 'http://localhost:8000/api';

async function loadPicturesHomepage(endpoint, id) {
    var idString = id.toString();
    var apiFetch = apiMain + endpoint + '/' + idString; // To build the API URL to the endpoint
    console.log("The API Fetch URL" + apiFetch);

    try {
        const response = await fetch(apiFetch); //Call the Get Routes in the service produktbild.js
        const data = response.json();

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