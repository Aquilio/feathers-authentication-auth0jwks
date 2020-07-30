const { promisify } = require('util');
const jwksClient = require('jwks-rsa');
const jsonwebtoken = require('jsonwebtoken');
const { AuthenticationService } = require('@feathersjs/authentication');
const { NotAuthenticated, GeneralError } = require('@feathersjs/errors');

const verifyJWT = promisify(jsonwebtoken.verify);

class Auth0JWKSAuthenticationService extends AuthenticationService {
  constructor(app, configKey) {
    super(app, configKey);
    const { auth0jwks } = this.configuration;

    this.client = jwksClient({
      cache: true,
      jwksUri: `https://${auth0jwks.domain}/.well-known/jwks.json`,
    });
  }

  getJWTOptions() {
    const { jwtOptions, auth0jwks } = this.configuration;
    return {
      audience: [
        `https://${auth0jwks.domain}/userinfo`,
        ...jwtOptions.audience,
      ],
      issuer: `https://${auth0jwks.domain}/`,
      algorithms: ['RS256'],
    };
  }

  getKey(header, cb) {
    this.client.getSigningKey(header.kid, (err, key) => {
      if (err) return cb(err, null);
      if (!key)
        return cb(GeneralError('`key` cannot be null or undefined'), null);
      const signingKey = key.publicKey || key.rsaPublicKey;
      cb(null, signingKey);
    });
  }

  async verifyAccessToken(accessToken, optsOverride) {
    const jwtOptions = this.getJWTOptions();
    const options = { ...jwtOptions, ...optsOverride };

    try {
      const isValid = await verifyJWT(
        accessToken,
        this.getKey.bind(this),
        options
      );
      return isValid;
    } catch (e) {
      throw new NotAuthenticated(e.message, e);
    }
  }

  async create(data, params) {
    const authStrategies =
      params.authStrategies || this.configuration.authStrategies;

    if (!authStrategies.length) {
      throw new NotAuthenticated(
        'No authentication strategies allowed for creating a JWT (`authStrategies`)'
      );
    }

    const authResult = await this.authenticate(data, params, ...authStrategies);

    if (authResult.accessToken) {
      return authResult;
    }

    throw new NotAuthenticated('No access token');
  }
}

module.exports.Auth0JWKSAuthenticationService = Auth0JWKSAuthenticationService;
