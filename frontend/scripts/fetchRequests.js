const apiMain = 'http://localhost:8000/api';

async function loadPicturesHomepage(endpoint, id) {
    var apiFetch = apiMain + endpoint;
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