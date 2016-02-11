var url = require('url');
var ldap = require('ldapjs');
var _ = require('lodash');
var debug = require('debug')('LDAPClient');

class LDAPClient {
  constructor(cfg) {
    let tlsOptions = {
      cert:   cfg.cert,
      key:    cfg.key,
    };
    let port = url.parse(cfg.url).port;
    if (port) {
      tlsOptions.port = port;
    }

    this.client = ldap.createClient({
      url: cfg.url,
      tlsOptions,
      timeout: 10 * 1000,
      reconnect: true,
    });
  }

  bind(user, password) {
    debug(`bind(${user}, <password>)`);
    return new Promise((accept, reject) => this.client.bind(
      user, password, err => {
      err ? reject(err) : accept();
    }));
  }

  search(base, options) {
    debug(`search(${base}, ${JSON.stringify(options)})`);
    return new Promise((accept, reject) => this.client.search(
      base, options, (err, res) => {
      err ? reject(err) : accept(res);
    }));
  }

  dnForEmail(email) {
    debug(`dnForEmail(${email})`);
    let userDn;
    return this.search(
      "dc=mozilla", {
      scope: 'sub',
      filter: '(&(objectClass=inetOrgPerson)(mail=' + email + '))',
      attributes: [],
      timeLimit: 10,
    }).then((res) => {
      return new Promise((accept, reject) => {
        res.on('searchEntry', entry => {
          userDn = entry.object.dn;
        });
        res.on('error', (err) => {
          reject(err);
        });
        res.on('end', result => {
          if (result.status !== 0) {
            return reject(new Error('LDAP error, got status: ' + result.status));
          }
          return accept(userDn);
        });
      });
    });
  }
}

module.exports = LDAPClient;
