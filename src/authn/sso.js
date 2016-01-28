import express from 'express'
import saml from 'passport-saml'
import passport from 'passport'
import assert from 'assert'
import User from './../user'

class SSOLogin {
  constructor(options) {
    assert(options, 'options are required');
    assert(options.cfg, 'options.cfg is required');
    assert(options.cfg.sso, 'options.cfg.sso is required');
    assert(options.cfg.sso.allowedGroups, 'options.cfg.sso.allowedGroups is required');
    assert(options.cfg.sso.issuer, 'options.cfg.sso.issuer is required');
    assert(options.cfg.sso.entryPoint, 'options.cfg.sso.entryPoint is required');
    assert(options.cfg.sso.certificate, 'options.cfg.sso.certificate is required');
    assert(options.ldapService, 'options.ldapService is required');

    this.allowedGroups = options.cfg.sso.allowedGroups;
    this.ldapService = options.ldapService;

    passport.use(new saml.Strategy({
      issuer: options.cfg.sso.issuer,
      path: '/sso/login',
      entryPoint: options.cfg.sso.entryPoint,
      cert: options.cfg.sso.certificate,
      skipRequestCompression: true,
      passReqToCallback: true
    }, this.samlCallback.bind(this)));
  }

  router() {
    let router = new express.Router();
    router.post('/login', passport.authenticate('saml', {
      successRedirect: '/',
      failureRedirect: '/',
      failureFlash: true
    }));
    return router;
  };

  async samlCallback(req, profile, done) {
    try {
      let user = User.get(req);
      user.ldapUser = profile['ldap-email'];

      let posixGroups = await this.ldapService.posixGroups(profile['ldap-email']);
      posixGroups.forEach(group => {
        if (this.allowedGroups.indexOf(group) !== -1) {
          user.addLDAPGroup(group);
        }
      });

      profile['ldap-groups'].forEach(group => {
        if (this.allowedGroups.indexOf(group) !== -1) {
          user.addLDAPGroup(group);
        }
      });
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }
}

module.exports = SSOLogin;
