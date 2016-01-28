import express from 'express'
import passport from 'passport'
import assert from 'assert'
import persona from 'passport-persona'
import Mozillians from 'mozillians-client'
import User from './../user'

class PersonaLogin {
  constructor(options) {
    assert(options, 'options are required');
    assert(options.cfg, 'options.cfg is required');
    assert(options.cfg.server, 'options.cfg.server is required');
    assert(options.cfg.server.publicUrl, 'options.cfg.server.publicUrl is required');
    assert(options.cfg.mozillians, 'options.cfg.mozillians is required');
    assert(options.cfg.mozillians.apiKey, 'options.cfg.mozillians.apiKey is required');
    assert(options.cfg.mozillians.allowedGroups,
        'options.cfg.mozillians.allowedGroups is required');

    // Mozillians client
    this.mozillians = new Mozillians(options.cfg.mozillians.apiKey);
    this.allowedGroups = options.cfg.mozillians.allowedGroups;

    // Persona/mozillians configuration
    passport.use(new persona.Strategy({
      audience: options.cfg.server.publicUrl,
      passReqToCallback: true
    }, this.personaCallback.bind(this)));
  }

  router() {
    let router = new express.Router();
    router.post('/login', passport.authenticate('persona', {
      successRedirect: '/',
      failureRedirect: '/?err=mozillians-lookup',
      failureFlash: true
    }));
    return router;
  }

  async personaCallback(req, email, done) {
    console.log("personalCallback", this);
    try {
      let user = User.get(req);

      // Find the user
      let userLookup = await this.mozillians.users({email});
      if (userLookup.results.length === 1) {
        let u = userLookup.results[0];
        if (u.is_vouched) {
          user.mozillianUser = u.username;
        }
      }

      if (!user.mozillianUser) {
        // If lookup failed we want to print a special error message
        return done(null, null);
      }

      // For each group to be considered we check if the user is a member
      let groupLookups = await Promise.all(
        this.allowedGroups.map(group => {
          return this.mozillians.users({email, group}).then(result => {
            result.group = group;
            return result;
          });
        })
      );
      groupLookups.forEach(g => {
        if (g.results.length === 1) {
          let u = g.results[0];
          if (u.is_vouched && u.username === user.mozillianUser) {
            user.addMozillianGroup(g.group);
          }
        }
      });

      done(null, user);
    } catch (err) {
      done(err, null);
    }
  };

}

module.exports = PersonaLogin;
