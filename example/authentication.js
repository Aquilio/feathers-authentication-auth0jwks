const {
  Auth0JWKSAuthenticationService,
  Auth0JWKSStrategy
} = require('../src');

module.exports = app => {
  const authentication = new Auth0JWKSAuthenticationService(app);

  authentication.register('auth0jwks', new Auth0JWKSStrategy());

  app.use('/authentication', authentication);
};
