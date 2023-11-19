const express = require("express");
const bcrypt = require("bcrypt");
const {
  getUserByEmail,
  getUserById,
} = require("../controllers/userController.js");
const { User, generateToken } = require("../models/userModel.js");
const jwt = "jsonwebtoken";
const nodemailer = require("nodemailer");

const router = express.Router();

// login - already existing users
router.post("/login", async (req, res) => {
  try {
    // To check whether the user  already exists in db or not
    const user = await getUserByEmail(req);
    if (!user) {
      return res.status(404).json({ error: "User does not exists." });
    }
    // To validate the password
    const validatePassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!validatePassword) {
      return res.status(404).json({ error: "Invalid Credentials." });
    }
    const token = generateToken(user._id);
    res.status(200).json({ message: "Logged in Successfully.", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

// signup - new user
router.post("/signup", async (req, res) => {
  try {
    // To check whether the user  already exists in db or not
    let user = await getUserByEmail(req);
    if (user) {
      return res.status(400).json({ error: "User Already Exists" });
    }

    // To generate a hashed password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // To store the email and password in the User db
    user = await new User({
      email: req.body.email,
      password: hashedPassword,
    }).save();
    const token = generateToken(user._id);
    res.status(201).json({ message: "Successfully Created.", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

// forgot-password
router.post("/forgot-password", async (req, res) => {
  try {
    // To check whether the user  already exists in db or not
    const user = await getUserByEmail(req);
    if (!user) {
      return res.status(404).json({ error: "User does not exists." });
    }
    // To generate a random string consist of some token and secret key
    const secret = "secret_key" + user.password;
    const token = jwt.sign({ email: user.email, id: user._id }, secret, {
      expiresIn: "5m",
    });

    // password reset link to be sent to the user via email
    const link = `http://localhost:5000/user/reset-password/${user._id}/${token}`;

    // to send the reset email to the user from the host
    var transporter = nodemailer.createTransport({
      service: "Yandex",
      auth: {
        user: "secondary2101@yandex.com",
        pass: "ysFcFze4L38483j",
      },
    });

    var mailOptions = {
      from: "secondary2101@yandex.com",
      to: user.email,
      subject: "Password Reset Link",
      text: link,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        console.log("Email sent: " + info.response);
      }
    });
    res.status(200).json({ message: "Password reset link sent.", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Internal Server Error." });
  }
});

// get reset-password routes
router.get("/reset-password/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  // To check whether the user  already exists in db or not
  const user = await User.findOne({ _id: id });
  if (!user) {
    return res.status(404).json({ error: "User does not exists." });
  }
  // To verify the random string sent via email using jwt
  const secret = "secret_key"+ user.password;
  try {
    const verify = jwt.verify(token, secret);
    // To load the html file where the form is displayed to enter the new password
    res.render("index", { email: verify.email, status: "Not Verified" });
  } catch (error) {
    res.send("Not Verified");
    console.log(error);
  }
});

// post reset-password routes
router.post("/reset-password/:id/:token", async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;
    // // To check whether the user exists in db or not
    const user = await User.findOne({ _id: id });
    if (!user) {
      return res.status(404).json({ error: "User does not exists." });
    }
    const secret = "secret_key" + user.password;
    try {
      const verify = jwt.verify(token, secret);
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      await User.updateOne({ _id: id }, { $set: { password: hashedPassword } });
      // This load the html file where the form is displayed to enter new password
      res.render("index", { email: verify.email, status: "verified" });
    } catch (error) {
      res.json({ status: "Something went wrong" });
      console.log(error);
    }
  });

//home
router.get("/", (req, res) => {
  res.send("connected");
});

module.exports = router;
