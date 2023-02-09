const clientDetails = require('./clientDetails.js');

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');

const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || "3000"; 

app.use(cors());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({limit: '50mb'}));
app.use(express.json({limit: '50mb'}));
app.use(express.urlencoded({limit: '50mb',extended: true }));

app.set('view engine', 'ejs');

app.use(session({
	secret: 'wiAaDjLTrX',
	resave: false,
	saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, next) => {
	next(null, user);
});

passport.deserializeUser((obj, next) => {
	next(null, obj);
});

function generateStrategy(clientIdentifier) {
    strategy = new Strategy({
        issuer: `https://${clientDetails['issuer']}/oauth2/default`,
        authorizationURL: `https://${clientDetails['issuer']}/oauth2/default/v1/authorize`,
        tokenURL: `https://${clientDetails['issuer']}/oauth2/default/v1/token`,
        userInfoURL: `https://${clientDetails['issuer']}/oauth2/default/v1/userinfo`,
        clientID: clientDetails['clients'][`${clientIdentifier}`]['clientId'],
        clientSecret: clientDetails['clients'][`${clientIdentifier}`]['clientSecret'],
        callbackURL: `${clientDetails['redirectUrl']}`,
        scope: 'openid profile'
    }, (issuer, profile, done) => {
        return done(null, profile);
    })
    return strategy;
};

checkAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) { return next() }
    res.redirect("/login")
};

app.use('/login', function login(req, res, next) {
    var clientIdentifier = req.headers.clientid || "client_2";
    var strategy = generateStrategy(clientIdentifier);
    passport.authenticate(strategy, {
        successRedirect: "/welcome",
        failureRedirect: "/login",
     })(req, res, next);
});

app.use('/callback', function login(req, res, next) {
    var clientIdentifier = req.headers.clientid || "client_2";
    var strategy = generateStrategy(clientIdentifier);
    passport.authenticate(strategy, {
        successRedirect: "/welcome",
        failureRedirect: "/login",
     })(req, res, next);
});

app.get('/logout', (req, res) => {
  req.logout();
  req.session.destroy();
  res.send('Logged Out successfully').status(200);
});

app.use('/welcome', checkAuthenticated, (req, res) => {
    const user = req.session['passport']['user'];
	res.render('welcome', user);
});

app.listen(PORT, () => console.log(`Server listening on port: ${PORT}`));