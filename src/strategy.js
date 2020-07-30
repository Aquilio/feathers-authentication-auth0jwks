const omit = require('lodash.omit');
const makeDebug = require('debug');
const { JWTStrategy } = require('@feathersjs/authentication');
const { NotAuthenticated } = require('@feathersjs/errors');

const debug = makeDebug('feathers-authentication-auth0jwks/strategy');

class Auth0JWKSStrategy extends JWTStrategy {
  get configuration() {
    const {
      entity,
      service,
      entityId,
      auth0jwks
    } = this.authentication.configuration;
    const config = super.configuration;

    return {
      entity,
      entityId,
      service,
      entityAuth0: auth0jwks.entityAuth0,
      domain: auth0jwks.domain,
      ...config
    };
  }

  verifyConfiguration() {
    const allowedKeys = [
      'header',
      'schemes',
      'entity',
      'entityId',
      'service',
      'entityAuth0',
      'domain'
    ];
    for (const key of Object.keys(this.configuration)) {
      if (!allowedKeys.includes(key)) {
        throw new Error(
          `Invalid Auth0JWKSStrategy option 'authentication.${this.name}.${key}'. Did you mean to set it in 'authentication.jwtOptions'?`
        );
      }
    }
  }

  async authenticate(authentication, params) {
    const authParams = omit(params, 'paginate');
    const authResult = await super.authenticate(authentication, authParams);
    authResult.authentication.strategy = 'auth0jwks';
    authResult.authentication.permissions =
      authResult.authentication.payload.permissions;
    return authResult;
  }

  async getEntity(id, params) {
    const { entity, entityId, entityAuth0 } = this.configuration;
    const entityService = this.entityService;

    debug('Getting entity with %s=%s', entityAuth0, id);

    if (entityService === null) {
      throw new NotAuthenticated('Could not find entity service');
    }

    const lookupParams = omit(params, 'provider');
    let result;

    if (entityAuth0 === entityService.id) {
      result = await entityService.get(id, lookupParams);
    } else {
      const lookup = await entityService.find({
        ...lookupParams,
        query: { [entityAuth0]: id, $limit: 1 }
      });
      result = Array.isArray(lookup) ? lookup[0] : lookup.data[0];
    }

    if (!params.provider) {
      return result;
    }

    return entityService.get(result[entityId], { ...params, [entity]: result });
  }
}

module.exports.Auth0JWKSStrategy = Auth0JWKSStrategy;
