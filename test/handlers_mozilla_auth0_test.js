const assume = require('assume');
const Handler = require('../src/handlers/mozilla-auth0');
const {encode} = require('../src/utils');

suite('handlers/mozilla-auth0', function() {
  suite('userFromProfile', function() {
    let handler = new Handler({
      name: 'mozilla-auth0',
      cfg: {
        handlers: {
          'mozilla-auth0': {
            domain:'login-test.taskcluster.net', 
            apiAudience: 'login-test.taskcluster.net',
            clientId: 'abcd',
            clientSecret: 'defg',
          },
        },
      },
    });

    test('user for ldap profile', function() {
      const user_id = 'ad|Mozilla-LDAP|foo';
      const user = handler.userFromProfile({
        email: 'foo@mozilla.com',
        email_verified: true,
        user_id,
        identities: [{provider: 'ad', connection: 'Mozilla-LDAP'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
    });

    test('user for email profile', function() {
      const user_id = 'email|foo';
      const user = handler.userFromProfile({
        email: 'foo@bar.com',
        email_verified: true,
        user_id,
        identities: [{provider: 'email', connection: 'email'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
    });

    test('user for google profile', function() {
      const user_id = 'google|foo';
      const user = handler.userFromProfile({
        email: 'foo@bar.com',
        email_verified: true,
        user_id,
        identities: [{provider: 'google-oauth2', connection: 'google-oauth2'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
    });

    test('user for github profile', function() {
      const user_id = 'github|0000';
      const user = handler.userFromProfile({
        nickname: 'octocat',
        user_id,
        identities: [{provider: 'github', connection: 'github'}],
      });

      assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}|octocat`);
    });

    test('user with user_id for which encoding is not identity', () => {
      ['abc@gmail.com|0000|test', 'abc@gmail.com|0000%2F|test']
        .forEach(user_id => {
          const user = handler.userFromProfile({
            email: 'abc@gmail.com',
            email_verified: true,
            user_id,
            identities: [{provider: 'google-oauth2', connection: 'google-oauth2'}],
          });

          assume(user.identity).to.equal(`mozilla-auth0/${encode(user_id)}`);
        });
    });
  });
});
