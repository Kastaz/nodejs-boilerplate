const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', {session: false} );
const requireSignin = passport.authenticate('local', {session: false});

module.exports = function(app) {
  app.get('/', requireAuth, function(request, response) {
    response.send({ hi: 'there' });
  });
  app.post('/signin', requireSignin, Authentication.signin);
  app.post('/adduser', Authentication.addUser);
}
