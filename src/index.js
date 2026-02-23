require("dotenv").config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const hbs = require('hbs');
const collection = require('./mongodb');
const { createModel } = require('./mlModel');

const app = express();
const session = require('express-session');

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));


const templatePath = path.join(__dirname, '../templates');

// view engine
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "hbs");
app.set("views", templatePath);

app.get('/', (req, res) =>{
    res.redirect('home')
});

app.get('/home', (req, res) =>{
    res.render('home', { user: req.session.user });
});
app.get('/login', (req, res) =>{
    res.render('login')
});

app.get('/signup', (req, res) =>{
    res.render('signup')
});

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect("/home");
        }

        res.clearCookie("connect.sid"); 
        res.redirect("/login");
    });
});

// Check DB users
app.get("/check-users", async (req, res) => {
    const users = await collection.find();
    console.log(users); // hashed passwords
    res.send("Check server console for user data");
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await collection.findOne({ email });
        if (!user) return res.send("User not found");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.send("Wrong password");

        // user info in session
        req.session.user = {
            id: user._id,
            fullname: user.fullname,
            email: user.email
        };

      
        res.redirect("/home");
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/signup", async (req, res) => {
    try {
        const { fullname, email, password, confirm_password } = req.body;

        if (password !== confirm_password) return res.send("Passwords do not match");

        const existingUser = await collection.findOne({ email });
        if (existingUser) return res.send("Email already registered");

        const hashedPassword = await bcrypt.hash(password, 10);

        const userData = {
            fullname,
            email,
            password: hashedPassword
        };

        await collection.create(userData);

        res.redirect("/login");
    } catch (error) {
        console.error("Signup error:", error);
        res.status(500).send("Internal Server Error");
    }
});


async function startServer() {
    await createModel(); // initializing ML model
    const port = 5000;
    app.listen(port, () => {
        console.log(`Server running on port: ${port}`);
    });
}

startServer();