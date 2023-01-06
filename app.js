// imports
require("dotenv").config({ path: "./config/.env" });
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("email-validator");
const passwordValidator = require("password-validator");

const app = express();

// config json response
app.use(express.json());

// models
const User = require("./models/User");

// public route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Well done! :D" });
});

// private route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  //check if user exists
  const user = await User.findById(id, "-password");
  if (!user) return res.status(404).json({ msg: "Usuário não encontrado!" });

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ msg: "Acesso negado!" });

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (err) {
    res.status(400).json({ msg: "Token inválido!" });
  }
}

// register
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // validations
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" });
  }
  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }
  if (password !== confirmPassword) {
    return res.status(422).json({ msg: "As senhas não correspondem!" });
  }
  if (!validator.validate(email))
    return res.status(422).json({ msg: "E-mail Inválido!" });

  // validate password
  var schema = new passwordValidator();
  schema
    .is()
    .min(8, "Precisa ter no mínimo 8 caracteres")
    .is()
    .max(100, "Precisa ter no máximo 100 caracteres")
    .has()
    .uppercase(1, "Precisa ter no mínimo 1 caractere maiúsculo")
    .has()
    .lowercase(1, "Precisa ter no mínimo 1 caractere minúsculo")
    .has()
    .symbols(1, "Precisa ter no mínimo 1 caractere especial")
    .has()
    .not()
    .spaces(0, "Não pode conter espaço");

  if (!schema.validate(password)) {
    return res.status(422).json({
      msg: "Senha inválida!",
      info: schema
        .validate(password, { details: true })
        .map((detail) => detail.message),
    });
  }

  // check if user exists
  const userExists = await User.findOne({ email: email });
  if (userExists)
    return res.status(422).json({ msg: "Esse e-mail já está cadastrado!" });

  // create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: "Erro no servidor" });
  }
});

// login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // validations
  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }
  if (!validator.validate(email))
    return res.status(422).json({ msg: "E-mail Inválido!" });

  // check if user exists
  const user = await User.findOne({ email: email });
  if (!user) return res.status(404).json({ msg: "Usuário não encontrado!" });

  // check password
  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) return res.status(422).json({ msg: "Senha inválida!" });

  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        username: user.name,
        userID: user._id,
      },
      secret,
      { expiresIn: "30m" }
    );

    res.status(200).json({ msg: "Login realizado com sucesso", token: token });
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: "Erro no servidor" });
  }
});

// credencials
const port = process.env.PORT;
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose.set("strictQuery", false);
mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.tmlqzgx.mongodb.net/database?retryWrites=true&w=majority`
  )
  .then(() => {
    console.log(new Date() + " - Conectado ao banco de dados");
    app.listen(port, () =>
      console.log(new Date() + ` - Rodando API na porta ${port}`)
    );
  })
  .catch((err) => console.log(err));
