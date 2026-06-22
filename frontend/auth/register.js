const { post } = require("../../backend/services/adresse");

async function register(event) {
  event.preventDefault();
  const username = document.getElementById("reg-username").value;
  const password = document.getElementById("reg-password").value;
  const firstname = document.getElementById("reg-vorname").value;
  const lastname = document.getElementById("reg-nachname").value;
  const city = document.getElementById("reg-city").value;
  const postcode = document.getElementById("reg-postcode").value;
  const street = document.getElementById("reg-street").value;
  const number = document.getElementById("reg-number").value;

  const res = await fetch("http://localhost:8000/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      password,
      firstname,
      lastname,
      city,
      postcode,
      street,
      number,
    }),
  });

  const data = await res.json();
  document.getElementById("result").innerText = data.message;
  if (res.ok) {
    localStorage.setItem("authToken", data.token);
  }
}
