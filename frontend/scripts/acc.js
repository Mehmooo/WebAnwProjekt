const apiMain = "http://localhost:8000/api";

var accountData = {};

const labels = {
  lastname: "Name",
  firstname: "Vorname",
  street: "Straße",
  city: "Stadt",
  email: "E-Mail",
};

var isEditing = false;

function parseJwt(token) {
  const base64Url = token.split(".")[1];
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const jsonPayload = decodeURIComponent(
    atob(base64)
      .split("")
      .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
      .join(""),
  );
  return JSON.parse(jsonPayload);
}

function getUserInfo() {
  const token = localStorage.getItem("authToken");
  if (!token) return null;
  return parseJwt(token);
}

async function loadAccountData(endpoint) {
  var apiFetch = apiMain + endpoint;
  console.log("The API Fetch URL: " + apiFetch);

  try {
    const response = await fetch(apiFetch);
    const data = await response.json();

    if (response.status === 200) {
      accountData = {
        lastname: data.nachname,
        firstname: data.vorname,
        street: data.adresse.strasse + " " + data.adresse.hausnummer,
        city: data.adresse.plz + " " + data.adresse.ort,
        email: data.email,
      };

      renderView();

      console.log("Account erfolgreich geladen");
    } else {
      console.log("Fehlgeschlagen siehe Status Code " + response.status);
    }
  } catch (error) {
    console.log(error);
  }
}

function renderView() {
  const container = document.querySelector(".personal-data-view");
  container.innerHTML = "";

  Object.keys(accountData).forEach((key) => {
    const p = document.createElement("p");
    p.textContent = labels[key] + ": " + accountData[key];
    container.appendChild(p);
  });
}

function renderEdit() {
  const container = document.querySelector(".personal-data-view");
  container.innerHTML = "";

  Object.keys(accountData).forEach((key) => {
    const row = document.createElement("div");
    row.classList.add("field-row");

    const label = document.createElement("label");
    label.textContent = labels[key];

    const input = document.createElement("input");
    input.type = "text";
    input.value = accountData[key];
    input.dataset.key = key;

    row.appendChild(label);
    row.appendChild(input);

    container.appendChild(row);
  });
}

async function saveData() {
  // Inputs in accountData übernehmen
  document.querySelectorAll(".personal-data-view input").forEach((input) => {
    const key = input.dataset.key;
    accountData[key] = input.value;
  });

  // Mapping zurück ins API-Format
  const payload = {
    id: getUserInfo().userId, // wichtig: muss vorhanden sein
    vorname: accountData.firstname,
    nachname: accountData.lastname,
    email: accountData.email,
    adresse: {
      id: accountData.addressId, // musst du ggf. beim Laden speichern!
    },
  };

  try {
    const res = await fetch(apiMain + "/person", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await res.json();

    if (res.ok) {
      console.log("Gespeichert ✔", data);
    } else {
      console.log("Fehler beim Speichern:", data);
    }
  } catch (err) {
    console.error("Network Fehler:", err);
  }
}

function toggleEdit() {
  const button = document.querySelector("#edit-btn");

  if (!isEditing) {
    renderEdit();
    button.textContent = "Speichern";
  } else {
    // hier kommt der endpoint rein
    saveData();
    renderView();
    button.textContent = "Persönliche Daten ändern";
  }

  isEditing = !isEditing;
}
