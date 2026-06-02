// create server
const HTTP_PORT = 3000;
const express = require("express");
const app = express();

// setting folder for static files like images, pdfs aso
app.use(express.static(__dirname + "/"));

var webServer = app.listen(HTTP_PORT, () => {
  console.log(
    "Frontend Server running, listening at localhost, port " + HTTP_PORT,
  );
  console.log("\nUsage: http://localhost:" + HTTP_PORT);
  console.log("\n\n-----------------------------------------");
  console.log("exit / stop Server by pressing 2 x CTRL-C");
  console.log("-----------------------------------------\n\n");
});
