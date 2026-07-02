const apiMain = "http://localhost:8000/api";

var accountData = {};

const labels = {
  lastname: "Name",
  firstname: "Vorname",
  street: "Straße",
  houseNumber: "Hausnummer",
  zip: "PLZ",
  city: "Ort",
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
  const apiFetch = apiMain + endpoint;
  console.log("The API Fetch URL: " + apiFetch);

  try {
    const response = await fetch(apiFetch);
    const data = await response.json();

    if (response.status === 200) {
      accountData = {
        lastname: data.nachname,
        firstname: data.vorname,
        street: data.adresse.strasse,
        houseNumber: data.adresse.hausnummer,
        zip: data.adresse.plz,
        city: data.adresse.ort,
        email: data.email,
        addressId: data.adresse.id,
      };

      renderView();

      console.log("Account erfolgreich geladen");
      console.log("neu");
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

  const fields = [
    {
      label: labels.lastname,
      value: accountData.lastname,
    },
    {
      label: labels.firstname,
      value: accountData.firstname,
    },
    {
      label: labels.street,
      value: `${accountData.street} ${accountData.houseNumber}`,
    },
    {
      label: "Stadt",
      value: `${accountData.zip} ${accountData.city}`,
    },
    {
      label: labels.email,
      value: accountData.email,
    },
  ];

  fields.forEach((field) => {
    const p = document.createElement("p");
    p.textContent = `${field.label}: ${field.value}`;
    container.appendChild(p);
  });
}

function renderEdit() {
  const container = document.querySelector(".personal-data-view");
  container.innerHTML = "";

  const rows = [
    ["lastname"],
    ["firstname"],
    ["street", "houseNumber"],
    ["zip", "city"],
    ["email"],
  ];

  rows.forEach((group) => {
    const row = document.createElement("div");
    row.classList.add("field-row");

    group.forEach((key) => {
      const wrapper = document.createElement("div");
      wrapper.classList.add("field");

      const label = document.createElement("label");
      label.textContent = labels[key];

      const input = document.createElement("input");
      input.type = "text";
      input.value = accountData[key] || "";
      input.dataset.key = key;

      wrapper.appendChild(label);
      wrapper.appendChild(input);

      row.appendChild(wrapper);
    });

    container.appendChild(row);
  });
}

async function saveData() {
  document.querySelectorAll(".personal-data-view input").forEach((input) => {
    const key = input.dataset.key;
    accountData[key] = input.value;
  });

  const payloadadresse = {
      id: accountData.addressId,
      strasse: accountData.street,
      hausnummer: accountData.houseNumber,
      plz: accountData.zip,
      ort: accountData.city,
    };

    console.log(payloadadresse);

  const payloadperson = {
    id: getUserInfo().userId,
    vorname: accountData.firstname,
    nachname: accountData.lastname,
    email: accountData.email,
    adresse: {
      id: accountData.addressId,
    },
  };

  console.log(payloadperson);

    try {
    const resAdresse = await fetch(apiMain + "/adresse", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payloadadresse),
    });

    if (!resAdresse.ok) {
      throw new Error("Adresse konnte nicht gespeichert werden.");
    }

    const resPerson = await fetch(apiMain + "/person", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payloadperson),
    });

    if (!resPerson.ok) {
      throw new Error("Person konnte nicht gespeichert werden.");
    }

      console.log("Gespeichert ✔");
      renderView();

    } catch (err) {
    console.error(err);
  }
}

function toggleEdit() {
  const button = document.querySelector("#edit-btn");

  if (!isEditing) {
    renderEdit();
    button.textContent = "Speichern";
  } else {
    saveData();
    button.textContent = "Persönliche Daten ändern";
  }

  isEditing = !isEditing;
}
