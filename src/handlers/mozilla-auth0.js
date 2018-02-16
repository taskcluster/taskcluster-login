const User = require('./../user');
const assert = require('assert');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const jwks = require('jwks-rsa');
const Debug = require('debug');
const auth0js = require('auth0-js');
const request = require('superagent');

const debug = Debug('handlers.mozilla-auth0');

class Handler {
  constructor({name, cfg}) {
    let handlerCfg = cfg.handlers[name];
    assert(handlerCfg.domain, `${name}.domain is required`);
    assert(handlerCfg.apiAudience, `${name}.apiAudience is required`);
    assert(handlerCfg.clientId, `${name}.clientId is required`);
    assert(handlerCfg.clientSecret, `${name}.clientSecret is required`);
    _.assign(this, handlerCfg);

    // use express-jwt to validate JWTs against auth0
    this.jwtCheck = expressJwt({
      secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${this.domain}/.well-known/jwks.json`,
      }),
      // expect to see our audience in the JWT
      audience: this.apiAudience,
      // and expect a token issued by auth0
      issuer: `https://${this.domain}/`,
      algorithms: ['RS256'],
      credentialsRequired: true,
    });

    this._managementApiExp = null;
    this._managementApi = null;
  }

  // Get a management API instance, by requesting an API token as needed
  // see https://auth0.com/docs/api/management/v2/tokens
  async getManagementApi() {
    if (this._managementApi && new Date().getTime() / 1000 < this._managementApiExp - 10) {
      return this._managementApi;
    }

    let res = await request.post(`https://${this.domain}/oauth/token`)
      .set('content-type', 'application/json')
      .send({
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        audience: `https://${this.domain}/api/v2/`,
      });

    let token = JSON.parse(res.text).access_token;
    if (!token) {
      throw new Error('did not receive a token from Auth0 /oauth/token endpoint');
    }

    // parse the token just enough to figure out when it expires
    let decoded = jwt.decode(token);
    let expires = decoded.exp;

    // create a new
    this._managementApi = new auth0js.Management({
      domain: this.domain,
      token: token,
    });
    this._managementApiExp = expires;

    return this._managementApi;
  }

  async profileFromIdentity(userId) {
    const a0 = await this.getManagementApi();
    const profile = new Promise((resolve, reject) =>
      a0.getUser(userId, (err, prof) => err ? reject(err) : resolve(prof)));

    return profile;
  }

  async userFromRequest(req, res) {
    // check the JWT's validity, setting req.user if sucessful
    try {
      await new Promise((resolve, reject) =>
        this.jwtCheck(req, res, (err) => err ? reject(err) : resolve()));
    } catch (err) {
      debug(`error validating jwt: ${err}`);
      return;
    }

    debug(`received valid access_token for subject ${req.user.sub}`);

    // TODO: remove full-user-credentials after updating tools, treeherder, and docs to reference the new scope
    // Bug 1437116
    let scopes = req.user.scope ? req.user.scope.split(' ') : [];
    if (!scopes.includes('full-user-credentials') && !scopes.includes('taskcluster-credentials')) {
      debug(`request did not have the 'full-user-credentials' or 'taskcluster-credentials' scope\
        ; had ${req.user.scope}`);
      return;
    }

    const profile = await this.profileFromIdentity(
      decodeURIComponent(req.user.sub)
    );

    if ('active' in profile && !profile.active) {
      debug('user is not active; rejecting');
      return;
    }

    const user = this.userFromProfile(profile);
    user.expires = new Date(req.user.exp * 1000);

    return user;
  }

  isIdentityProviderRecognized({provider, connection}) {
    if (
      provider === 'ad' && connection === 'Mozilla-LDAP' ||
      // The 'email' connection corresponds to a passwordless login.
      provider === 'email' && connection === 'email' ||
      provider === 'google-oauth2' && connection === 'google-oauth2' ||
      provider === 'github' && connection === 'github'
    ) {
      return true;
    }

    return false;
  }

  async userFromIdentity(identity) {
    const profile = await this.profileFromIdentity(identity);
    const user = this.userFromProfile(profile);

    return user;
  }

  userFromProfile(profile) {
    const user = new User();

    // we recognize a few different kinds of 'identities' that auth0 can send our way.
    // we do not ever expect to have more than one identity in this array, in a practical sense.
    for (const identity of profile.identities) {
      if (this.isIdentityProviderRecognized(identity)) {
        user.identity = `mozilla-auth0/${encodeURIComponent(profile['user_id'])}`;

        if (profile['user_id'].startsWith('github')) {
          user.identity += `/${profile.nickname}`;
        }
      }
    }

    if (!user.identity) {
      debug('No recognized identity providers');
      return;
    }

    // take a user and attach roles to it
    this.addRoles(profile, user);

    return user;
  }

  addRoles(profile, user) {
    // grant the everybody role to anyone who authenticates
    user.addRole('everybody');

    const mozGroupPrefix = 'mozilliansorg_';
    const mozGroups = [];
    const ldapGroups = [];

    // Non-prefixed groups are what is known as Mozilla LDAP groups. Groups prefixed by a provider
    // name and underscore are provided by a specific group engine. For example,
    // `providername_groupone` is provided by `providername`. Per https://goo.gl/bwWjvE.
    // For our own purposes, if the prefix is not mozilliansorg. then we treat it as an ldap group
    profile.groups && profile.groups.forEach(group => {
      // capture mozillians groups
      if (group.indexOf(mozGroupPrefix) === 0) {
        mozGroups.push(group.replace(mozGroupPrefix, ''));
      } else {
        // treat everything else as ldap groups
        ldapGroups.push(group);
      }
    });

    user.addRole(`mozilla-user:${user.identityId}`);
    ldapGroups.forEach(group => user.addRole(`mozilla-group:${group}`));

    // add mozillians roles to everyone
    mozGroups.map(group => {
      const str = group.replace(mozGroupPrefix, '');

      user.addRole(`mozillians-group:${str}`);
    });
  }
}

module.exports = Handler;
