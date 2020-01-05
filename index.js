const express = require("express");
const Joi = require("@hapi/joi");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = 3000;

mongoose.connect("mongodb+srv://your_connection_string", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const UserSchema = new mongoose.Schema({
  fullname: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true }
});

const User = mongoose.model("user", UserSchema);

app.use(express.json());

const registrationSchema = Joi.object({
  fullname: Joi.string().required(),
  email: Joi.string()
    .required()
    .email(),
  password: Joi.string()
    .min(6)
    .required()
});

const tokenVerifier = (req, res, next) => {
  const token = req.header("auth_token");
  if (!token) return res.status(401).send("Access Denied");

  try {
    const verified = jwt.verify(token, "OUR_VERY_SECURED_SECRET_KEY");
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).send("Invalid Token");
  }
};

app.post("/register", async (req, res) => {
  const { error } = registrationSchema.validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const emailExists = await User.findOne({ email: req.body.email });
  if (emailExists) return res.status(400).send("Email already exists");

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  const user = new User({
    fullname: req.body.fullname,
    email: req.body.email,
    password: hashedPassword
  });
  try {
    const savedUser = await user.save();
    res.send(savedUser);
  } catch (error) {
    res.status(400).send(error);
  }
});

app.post("/login", async (req, res) => {
  // TO-Do : Validate login

  // Check if user exists
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send("User does not exists");

  //check if password is correct
  const passwordCheck = await bcrypt.compare(req.body.password, user.password);
  if (!passwordCheck) return res.status(400).send("Password not correct");

  //Create a token
  const token = jwt.sign(
    { _id: user._id, email: user.email },
    "OUR_VERY_SECURED_SECRET_KEY"
  );

  res.header("auth_token", token).send(token);
});

app.get("/dashboard", tokenVerifier, (req, res) => {
  res.send("VERY CONFIDENTIAL DATA");
});

app.listen(port, () => {
  console.log(`Auth APIs listening on port ${port}`);
});
