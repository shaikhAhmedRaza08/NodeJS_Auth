const express = require('express');
const env = require('../environment');
const bcrypt = require('bcrypt');
const { pool } = require('./helper/db');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');
const initializePassport = require('../passportConfig')
const app = express();

initializePassport(passport);

app.set('view engine', 'ejs');
app.use(express.urlencoded({
    extended: false
}));

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


app.use(flash());

app.get('/', (req, res) => {
    res.render('../src/views/index');
});

app.get('/user/dashboard',checkNotAuthenticated, (req, res) => {
    res.render('../src/views/dashboard', { name: req.user.name })
});

app.get('/user/login',checkAuthenticated, (req, res) => {
    res.render('../src/views/login');
});

app.get('/user/logout', (req, res) => {
    req.logOut();
    req.flash('success_msg', 'You have logged out');
    res.redirect('/user/login');
})

app.get('/user/register', checkAuthenticated, (req, res) => {
    res.render('../src/views/register')
});


app.post('/user/register', async (req, res) => {
    let { name, email, password, confirmPassword } = req.body;
    console.log({
        name,
        email,
        password,
        confirmPassword
    });

    let errors = [];
    if (!name || !email || !password || !confirmPassword) {
        errors.push({ message: "Please enter all fields" });
    }
    if (password.length < 6) {
        errors.push({ message: "Password should be a least 6 characters" });
    }
    if (password != confirmPassword) {
        errors.push({ message: "Passwords do not match" });
    }
    if (errors.length > 0) {
        res.render('../src/views/register', { errors })
    } else {
        // All the form validations has passed 
        let hashedPassword = await bcrypt.hash(password, 10);
        console.log('hashedPassword', hashedPassword);
        pool.query(`SELECT * FROM auth."Users" 
        WHERE email = $1`, [email], (err, result) => {
            if (err) {
                throw err;
            }
            console.log(result.rows);
            let user = result.rows.find(user => user.email === email);
            console.log("user: ", user)
            if (user !== undefined) {
                errors.push({ message: "This email has already been used" });
                return res.render('../src/views/register', { errors })
            } else {
                pool.query(
                    `INSERT INTO auth    ."Users" (name, email, password)
                    VALUES ($1, $2, $3)
                    RETURNING id, password`, [name, email, hashedPassword], (err, result) => {
                    if (err) {
                        throw err;
                    }
                    console.log("DB Response: ", result.rows);
                    req.flash('success_msg', 'You are now registered. Please Login.');
                    res.redirect('/user/login');
                }
                )
            }
        })
    }
});

app.post('/user/login', passport.authenticate('local', {
    successRedirect: '/user/dashboard',
    failureRedirect: '/user/login',
    failureFlash: true
}));


function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return res.redirect('/user/dashboard');
    }

    next();
}

function checkNotAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return next();
    }

    res.redirect('/user/login');
}

app.listen(env.port, () => {
    console.log(`Server running at http://localhost:${env.port}`);
})