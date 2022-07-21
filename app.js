require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');     //required for authentication;
const passport = require('passport');          //we don't need to require passport-local since it's a dependency needed by passport-local-mongoose;
const passportLocalMongoose = require('passport-local-mongoose');    
const GoogleStrategy = require('passport-google-oauth20').Strategy; //Adding the Google Strategy for authentication using a Google account;
const findOrCreate = require('mongoose-findorcreate');    //Require this package for the Google-Passport package to work;

const app = express();

app.use(express.static("public"));          //to style on our website using a static generator;
app.set('view engine', 'ejs');              //to use ejs for re-rendering and execution of pages;
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({                       //app.use(session) has to be added AFTER the other app uses and set;
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());       //initialize is a passport function;
app.use(passport.session());         //used to manage our sessions;

mongoose.connect(process.env.MONGO_URI); //Connecting the database


const userSchema = new mongoose.Schema({ //Object created using the Mongoose Schema class
  email: String,                        //It gives the option to use more functions
  password: String,
  googleId: String,                    //Added this part so that we can save the Google ID in OUR database.
  secret: String                      //We modified the Schema so that we can store the user's secret.
});

userSchema.plugin(passportLocalMongoose);   //To give the option to HASH and SALT passwords and add users to MongoDB
userSchema.plugin(findOrCreate);          //Added the plugin for the package to work.

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());


passport.serializeUser(function(user, done) {   //it can work with ANY kind of authentication, not just local.
    done(null, user.id);                        //Creates the cookie and stores information
});

passport.deserializeUser(function(id, done) {  //Crumbles de cookie and gets the info
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({ //IMPLEMENTING THE GOOGLE STRATEGY.
    clientID: process.env.CLIENT_ID,   
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://authenticationandsecurity.herokuapp.com/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {                  //The app creates the user in our database;
    console.log(profile);
    User.findOrCreate({ googleId: profile.id, username: profile.name.givenName}, function (err, user) { //This is not a Mongoose model. We had to implement the findOrCreate package to
      return cb(err, user);                                           //verify if it's an existing client within our database using the google profile id;
    });
  
  }
));

///Routes
app.get('/', function (req, res) {
  res.render('home');
})

app.get('/auth/google',                                      //We are telling to the get method to use the google strategy
  passport.authenticate('google', { scope: ['profile'] })); //to authenticate the user through the scope by obtaining the google profile: id + email;

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),  //After the authentication with google it gets redirected to /auth/google/secrets
    function(req, res) {                                          //and it gets authenticated locally and SAVE the login session. The Google authentication has already completed.
      res.redirect('/secrets'); // Successful authentication, redirected to secrets. Go to line 100 and line 50 for the function to be triggered.
    });


app.get('/login', function (req, res) {
  res.render('login');
})

app.post('/login', function (req, res) { //For regular access with password and username

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  //passport
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
      };
    });
});

app.get('/register', function (req, res) {
  res.render('register');
})

app.get('/secrets', function (req, res) { //LEVEL 6
  //We are looking for the secret fields that are not null;
  User.find({'secret':{$ne:null}}, function (err, foundUsers) {//We are gonna find all the users' secrets that have been submitted in the database;
    if (err) {
      console.log(err);
    }else {
      if (foundUsers) {
        res.render("secrets", {userWithSecrets: foundUsers}); //we are rendering this to our secrets.ejs file;
      };
    };
  });
}); //Everyone, logged in or not, will have access to see the secrets. But, only the ones registered and logged in will be able to post;

app.get('/submit', function (req, res) {
  if (req.isAuthenticated()) { //passport authenticates the user. //this is where that process is generated.
    res.render('submit');
  }else {
    res.redirect("/login");
  }
})

app.post('/submit', function (req, res) {
  const userSecret = req.body.secret; //We are catching the secret from the submit page;
  // console.log(req.user.id);
  User.findById(req.user.id, function (err, foundUser) { //The user is searched in our database by using it's ID.
    if (err) {
      console.log(err);
    }else {
      if (foundUser) {
        foundUser.secret = userSecret; //we are adding the submited secret to the User's database by creating a new field;
        foundUser.save(function () {
          res.redirect('/secrets'); //When we save the user in our database, then he gets redirected to the secrets page;
        });

      };
    };
  });

});

app.get("/logout", function (req, res) { //For logout button
  //function from passportjs
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
  });
  res.redirect("/");
})

app.post("/register",function (req, res) {
  //Middleware, we don't have to interact with MongoDB;
  //function comes from passport-local-mongoose       //password         //This function returs a 'user';
  User.register({username: req.body.username}, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () { //It authenticates vrs the local database (usersDB);
        res.redirect("/secrets");
      });
    }
  });
});


app.listen(process.env.PORT, function () {
  console.log("Server started on port 3000");
})


// Documentation used:
// https://www.passportjs.org/tutorials/password/logout/
// https://www.npmjs.com/package/express-session
// https://www.npmjs.com/package/passport-local-mongoose
// https://www.npmjs.com/package/mongoose-findorcreate
// https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize
