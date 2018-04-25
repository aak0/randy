const express = require("express");
const app = express();
const path = require("path");
const helmet = require("helmet")

app.use(helmet())
app.use(express.static(path.join(__dirname, "public")));

app.listen(process.env.PORT,
  () => console.log(`Example app listening on port ${process.env.PORT}`));