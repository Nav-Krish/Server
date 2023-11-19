const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
});


const User = new mongoose.model("user", userSchema);

// To generate a token for each user
const generateToken = (id) => {
  return jwt.sign({ id }, "secret_key");
};

module.exports = { User, generateToken };