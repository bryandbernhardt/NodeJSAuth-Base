// imports
require("dotenv").config({ path: "./config/.env" });
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.get("/", (req, res) => {
  res.status(200).json({ msg: "Well done! :D" });
});

const port = 3000;
app.listen(port, () => console.log(`Rodando na porta ${port}`));
