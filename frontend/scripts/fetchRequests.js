const apiMain = 'http://localhost:8000/api';

async function loadPicturesHomepage(endpoint, id) {
    console.log("In der fetchRequests.js")
    var idString = id.toString();
    console.log("Der ID String ist: " + idString);
    var apiFetch = apiMain + endpoint + '/' + idString;
    console.log("API Fetch Link: " + apiFetch);

    try {
        const response = await fetch(apiFetch);
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