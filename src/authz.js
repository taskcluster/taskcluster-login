/**
 * The authorizer is responsible for taking User objects that only have
 * an identity set, and adding a collection of roles based on that
 * identity.
 */
class Authorizer {
  constructor(cfg) {
  }

  async setup() {
  }

  /**
   * Authorize the given user.
   * This method takes a User and attaches roles to it
   */
  async authorize(user) {
    const email = user.identityId;

    // grant the everybody role to anyone who authenticates
    user.addRole('everybody');

    const mozGroupPrefix = 'mozilliansorg_';
    const mozGroups = [];
    const ldapGroups = [];

    // Non-prefixed groups are what is known as Mozilla LDAP groups.
    // Groups prefixed by a provider name and underscore are provided
    // by a specific group engine. For example `providername_groupone`
    // is provided by `providername`.
    // Per https://goo.gl/bwWjvE
    user.groups.forEach(group => {
      // capture mozillians groups
      if (group.indexOf(mozGroupPrefix) === 0) {
        mozGroups.push(group.replace(mozGroupPrefix, ''));
      } else if (group.indexOf('_') === -1) {
        // ignore all other providers (e.g., workday_)
        ldapGroups.push(group);
      }
    });

    if (user.identity.toLowerCase().includes('mozilla-ldap')) {
      user.addRole(`mozilla-user:${email}`);
      ldapGroups.forEach(group => user.addRole(`mozilla-group:${group}`));
    } else {
      user.addRole(`mozillians-user:${email}`);
    }

    // add mozillians roles to everyone
    mozGroups.map(group => {
      const str = group.replace(mozGroupPrefix, '');

      user.addRole(`mozillians-group:${str}`);
    });
  }

  /**
   * A list of identity providers for which this authorizer is responsible
   */
  get identityProviders() {
    return ['mozilla-ldap', 'email', 'github'];
  }
}

module.exports = Authorizer;
