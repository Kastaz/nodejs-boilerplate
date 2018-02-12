const jwt = require('jwt-simple');
const config = require('../config');
const User = require('../models/user');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  // sub = subject, object which we are talking about to encrypt, iat = issued at time, when
  return jwt.encode({ sub:user.id, iat: timestamp }, config.secret);
}

exports.signin = function(request, response, next) {
  // user has already had their email and pass auth'd
  // we just need to give them a token
  response.send({ token: tokenForUser(request.user) });
}

exports.addUser = function(request, response, next) {
  const email = request.body.email;
  const password = request.body.password;

  if( !email || !password ) {
    return response.status(422).send({ error: 'You must provide email and password'});
  }

  // see if a user with email exist,
  User.findOne({ email: email }, function(error, existingUser) {
    if(error) {
      return next(error);
    }

  // if exist return error,
    if(existingUser) {
      return response.status(422).send( {error: 'Email is in use' });
    }

  // if does NOT exist, create and save record
    const user = new User({
      email: email,
      password: password
    });

    user.save( function(error) {
      if(error) { return next(error); }

  // respond to req indicatinc the user was created
      response.json({ token: tokenForUser(user) });
    });

  });

}
