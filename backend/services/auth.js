const helper = require("../helper.js");
const AuthDao = require("../dao/authDAO.js");
const express = require("express");
var serviceRouter = express.Router();

console.log(" Service Auth ");

serviceRouter.post("/register", async function (req, res) {
  console.log("Registering user...");

  const authDao = new AuthDao(req.app.locals.dbConnection);

  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password are required" });
    }
    const hashedPassword = await helper.hashPassword(password);
    const obj = await authDao.register(username, hashedPassword); //Call Function in the DAO
    res.status(200).json({ message: "Benutzer erfolgreich registriert! 🎉" });
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
    const passwordMatch = password === obj.passwort; // For simplicity, using plain text comparison. In production, use hashed passwords!
    if (!passwordMatch) {
      return res.status(401).json({ message: "Ungültige Anmeldedaten" });
    } else {
      res.status(200).json({ message: "Benutzer erfolgreich eingeloggt! 🎉" });
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
