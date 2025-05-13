require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 24 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: { secret: mongodb_session_secret }
});

app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}));

function isValidSession(req) {
  return req.session.authenticated;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) next();
  else res.redirect('/');
}

function isAdmin(req) {
  return req.session.user_type === 'admin';
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
    return;
  }
  next();
}

app.get('/', (req, res) => {
  res.render("index", { username: req.session.username });
});

app.get('/signup', (req, res) => res.render("signup"));

app.get('/login', (req, res) => res.render("login"));

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/members', sessionValidation, (req, res) => {
  const images = [
    "/public/images/cat1.gif",
    "/public/images/cat2.gif",
    "/public/images/cat3.gif"
  ];
  res.render("members", { username: req.session.username, images });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
  const users = await userCollection.find({}).toArray();
  res.render("admin", { users });
});

app.post('/promote', sessionValidation, adminAuthorization, async (req, res) => {
  const schema = Joi.string().alphanum().max(20).required();
  const validation = schema.validate(req.body.username);
  if (validation.error) {
    return res.render("errorMessage", { error: "Invalid username input." });
  }

  const { username } = req.body;
  await userCollection.updateOne({ username }, { $set: { user_type: "admin" } });
  res.redirect('/admin');
});

app.post('/demote', sessionValidation, adminAuthorization, async (req, res) => {
  const schema = Joi.string().alphanum().max(20).required();
  const validation = schema.validate(req.body.username);
  if (validation.error) {
    return res.render("errorMessage", { error: "Invalid username input." });
  }

  const { username } = req.body;
  await userCollection.updateOne({ username }, { $set: { user_type: "user" } });
  res.redirect('/admin');
});

app.post('/submitUser', async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(20).required(),
    password: Joi.string().max(20).required(),
    email: Joi.string().email().required()
  });

  const validationResult = schema.validate({ username, password, email });
  if (validationResult.error != null) {
    res.render("errorMessage", { error: validationResult.error.details[0].message });
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
    email: email,
    user_type: "user"
  });

  req.session.authenticated = true;
  req.session.username = username;
  req.session.user_type = "user";
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

app.post('/loggingin', async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().max(20).required(),
    password: Joi.string().max(20).required()
  });

  const validationResult = schema.validate({ username, password });
  if (validationResult.error != null) {
    res.render("errorMessage", { error: "Invalid username/password input." });
    return;
  }

  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, user_type: 1 }).toArray();

  if (result.length != 1) {
    res.render("errorMessage", { error: "Invalid email/password combination." });
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.user_type = result[0].user_type;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  } else {
    res.render("errorMessage", { error: "Invalid email/password combination." });
    return;
  }
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
