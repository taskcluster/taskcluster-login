const taskcluster = require('taskcluster-client');
const scopeUtils = require('taskcluster-lib-scopes');
const User = require('./user');
const {CLIENT_ID_PATTERN} = require('./utils');
const Debug = require('debug');

const debug = Debug('scanner');

async function scanner(cfg, handlers) {
  // * get the set of identityProviderIds
  // * for each:
  //   * fetch all clients
  //   * for each identity:
  //     * get roles from providers, expand
  //     * for each client in that identity:
  //       * get, verify client.expandedScopes satisfied by identity's expandedScopes

  // NOTE: this function performs once auth operation at a time.  It is better
  // for scans to take longer than for the auth service to be overloaded.
  let auth = new taskcluster.Auth({credentials: cfg.app.credentials});

  const scan = async h => {
    const handler = handlers[h];
    const clients = await auth.listClients({prefix: handler.identityPrefix});

    // iterate through the clients, constructing a new User as necessary, comparing
    // the client's scopes to the User's scopes and disabling where necessary.
    let user, userScopes;

    for (let client of clients) {
      debug('examining client', client.clientId);
      if (!client.clientId.match(CLIENT_ID_PATTERN) || client.disabled) {
        continue;
      }

      // when client has a github login, `patternMatch` will have an extra index entry with the user's GH username
      // e.g., ['mozilla-auth0/github|0000/helfi92, 'mozilla-auth0/github|0000', 'helfi92']
      const patternMatch = CLIENT_ID_PATTERN.exec(client.clientId);

      if (!user || user.identity !== patternMatch.slice(1).join('/')) {
        user = await User.getUser(client.clientId, handler);
        userScopes = (await auth.expandScopes({scopes: user.scopes()})).scopes;

        debug('..against user', user.identity);
      }

      // if this client's expandedScopes are not satisfied by the user's expanded
      // scopes, disable the client.
      if (!scopeUtils.scopeMatch(userScopes, [client.expandedScopes])) {
        await auth.disableClient(client.clientId);
      }
    }
  };

  Object
    .keys(cfg.handlers)
    .map(scan);
}

module.exports = scanner;
