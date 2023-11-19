const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const router = require('./routes/userRoute')

const app = express();
const PORT = 5000

app.use(cors({
    origin : "*",
    credentials : true,
    methods :["GET", "POST", "DELETE", "PUT", "PATCH"],
}))


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect('mongodb+srv://navanethakrishnan11:qwerty1234!@cluster0.h136z2e.mongodb.net/')
.then(() => {
    console.log("Connected to database");
})
.catch((error) => {
    console.log("Error connecting to database", error);
})

app.use("/user", router);



app.listen(PORT, () => {
    console.log("Server is running in Port:",PORT);
})