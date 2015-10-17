import express from 'express'
import passport from 'passport'
import _ from 'lodash'
import sslify from 'express-sslify'
import http from 'http'
import path from 'path'
import session from 'cookie-session'
import config from 'taskcluster-lib-config'
import persona from 'passport-persona'
import bodyParser from 'body-parser'
import saml from 'passport-saml'

require('source-map-support').install();

let launch = async (profile) =>  {
  // Load configuration
  let cfg = config({profile})

  // Create application
  let app = express();

  // Trust proxy
  app.set('trust proxy', cfg.server.trustProxy);

  // ForceSSL if required suggested
  if (cfg.server.forceSSL) {
    app.use(sslify.HTTPS(cfg.server.trustProxy));
  }


  // Setup views and assets
  app.use('/assets', express.static(path.join(__dirname, '..', 'assets')));
  app.set('views', path.join(__dirname, '..', 'views'));
  app.set('view engine', 'jade');

  // Parse request bodies (required for passport-persona)
  app.use(bodyParser.urlencoded({extended: false}));

  // Store session in a signed cookie
  app.use(session({
    name: 'taskcluster-login',
    keys: cfg.app.cookieSecrets,
    secure: cfg.server.forceSSL,
    secureProxy: cfg.server.trustProxy,
    httpOnly: true,
    signed: true,
    maxAge: 3 * 24 * 60 * 60 * 1000
  }));

  // Initially passport
  app.use(passport.initialize());
  app.use(passport.session());

  // Read and write user from signed cookie
  passport.serializeUser((user, done) => done(null, ensureUser(user)));
  passport.deserializeUser((user, done) => done(null, ensureUser(user)));

  // Ensure that we have a valid user structure
  let ensureUser = (user = {}) => {
    return _.defaults(user, {
      persona: [],
      github: null,
      ssoUser: null,
      ssoGroups: [],
    });
  };

  // Persona configuration
  passport.use(new persona.Strategy({
    audience: cfg.server.publicUrl,
    passReqToCallback: true
  }, (req, email, done) => {
    let user = ensureUser(req.user);
    user.persona = _.union(user.persona, [email]);
    done(null, user);
  }));
  app.post('/login/persona', passport.authenticate('persona', {
    successRedirect: '/',
    failureRedirect: '/',
    failureFlash: true
  }));


  // SSO configuration
  passport.use(new saml.Strategy({
    issuer: cfg.sso.issuer,
    path: '/login/sso',
    entryPoint: cfg.sso.entryPoint,
    cert: cfg.sso.certificate,
    passReqToCallback: true
  }, (req, profile, done) => {
    console.log("authenticated profile: %j", profile);
    let email = profile['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'];
    let user = ensureUser(req.user);
    if (email) {
      user.ssoUser = email;
      done(null, user);
    }
    done(null, null);
  }));
  app.post('/login/sso', passport.authenticate('saml', {
    successRedirect: '/',
    failureRedirect: '/',
    failureFlash: true
  }));

  app.get('/sso-login', passport.authenticate('saml', {
    failureRedirect:  '/',
    failureFlash: true
  }), (req, res) => {
    res.redirect('/');
  });




  // Render index
  app.get('/', (req, res) => {
    console.log(req.user);
    res.render('index', {
      query: req.query
    });
  });

  // Create server and start listening
  let server = http.createServer(app);
  await new Promise((accept, reject) => {
    server.listen(cfg.server.port, accept);
    server.once('error', reject);
  });
  console.log("Listening on port: " + cfg.server.port);
};


if (!module.parent) {
  launch(process.argv[2]).catch(err => {
    console.log("Server crashed: " + err.stack);
  }).catch(() => process.exit(1));
}

module.exports = launch;
