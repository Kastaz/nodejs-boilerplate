const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// setup options for local strategy
const localOptions = {
  usernameField: 'email'
};
// create local strategy
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  // verify email and password, call done with that user,
  // if its NOT correct, call done with false
  User.findOne({ email: email }, function(error, user) {
    if(error) {
      return done(error);
    }

    if(!user) {
      return done(null, false);
    }

    // compare passwords - is 'password' equal to user.password?
    user.comparePassword(password, function(error, isMatch) {
      if(error) {
        return done(error);
      }
      if(!isMatch) {
        return done(null, false);
      }

      return done(null, user);
    });
  });
});

// passport is a library to centralize the logic for checking if user is logged in,
// strategy is a method for authenticating a user, with passport-jwt we will verify user with JSON Web Token
// there are a lot more plugins for checking verification like gmail, facebook, etc.

// setup options for jwt strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// create jwt strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // see if user ID in the payload exists in our db
  // if it does, call 'done' with that user
  // otherwise, call 'done' without a user object
  User.findById(payload.sub, function(error, user) {
    if(error) {
      return done(error, false);
    }

    if(user) {
      done(null, user);
    } else {
      done(null, false);
    }

  });
});


// tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
