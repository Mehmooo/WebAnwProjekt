const helper = require("../helper.js");
const AuthDao = require("../dao/authDao.js");
const express = require("express");
const AdresseDao = require("../dao/adresseDao.js");
const { post } = require("./adresse.js");
const BenutzerDao = require("../dao/benutzerDao.js");
const PersonDao = require("../dao/personDao.js");
var serviceRouter = express.Router();
const jwt = require("jsonwebtoken");
const { token } = require("morgan");
const JWT_SECRET = "secret";

console.log(" Service Auth ");

serviceRouter.post("/register", async function (req, res) {
  console.log("Registering user...");

  const authDao = new AuthDao(req.app.locals.dbConnection);
  const adresseDao = new AdresseDao(req.app.locals.dbConnection);
  const personDao = new PersonDao(req.app.locals.dbConnection);
  const benutzerDao = new BenutzerDao(req.app.locals.dbConnection);

  try {
    const {
      username,
      password,
      firstname,
      lastname,
      city,
      postcode,
      street,
      number,
    } = req.body;
    if (
      !username ||
      !password ||
      !firstname ||
      !lastname ||
      !city ||
      !postcode ||
      !street ||
      !number
    ) {
      return res.status(400).json({ message: "some information is missing" });
    }
    console.log("adresseDao aufrufen");
    const adresseId = adresseDao.create(street, number, postcode, city);
    console.log("personDao aufrufen");
    const personId = personDao.create(firstname, lastname, adresseId, username);
    console.log("password hashen und AuthDAO aufrufen");
    const hashedPassword = await helper.hashPassword(password);
    const obj = await authDao.register(username, hashedPassword, personId); //Call Function in the DAO
    const token = jwt.sign(
      { userId: obj.userId, username: obj.username },
      JWT_SECRET,
      { expiresIn: "1h" },
    );
    res
      .status(200)
      .json({ message: "Benutzer erfolgreich registriert! 🎉", token });
  } catch (ex) {
    res.status(400).json({
      fehler: true,
      nachricht: ex.message,
    });
  }
});

serviceRouter.post("/login", async function (req, res) {
  console.log("Logging in user...");

  const authDao = new AuthDao(req.app.locals.dbConnection);

  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password are required" });
    }
    const obj = await authDao.findByUsername(username); //Call Function in the DAO
    if (!obj) {
      return res.status(401).json({ message: "Ungültige Anmeldedaten" });
    }
    console.log("User infos: ", obj);
    /*const passwordMatch = await helper.comparePassword(
        password,
        obj.passwort,
      );*/
    const passwordmatch = password === obj.passwort; // For simplicity, using plain text comparison. In production, use hashed passwords!
    if (!passwordmatch) {
      return res.status(401).json({ message: "Ungültige Anmeldedaten" });
    } else {
      const token = jwt.sign(
        { userId: obj.userId, username: obj.username },
        JWT_SECRET,
        { expiresIn: "1h" },
      );
      res
        .status(200)
        .json({ message: "Benutzer erfolgreich eingeloggt! 🎉", token });
    }
  } catch (ex) {
    console.error("Error during login: ", ex);
    res.status(500).json({
      fehler: true,
      nachricht: ex.message,
    });
  }
});

module.exports = serviceRouter;
