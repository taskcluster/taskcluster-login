const taskcluster = require('taskcluster-client');
const scopeUtils = require('taskcluster-lib-scopes');
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

  const clients = await auth.listClients({prefix: 'mozilla-auth0/'});

  // iterate through the clients, constructing a new User as necessary, comparing
  // the client's scopes to the User's scopes and disabling where necessary.
  let user, userScopes;
  // the second capturing group is used to catch a user's github username
  let idPattern = /^([^\/]*\/[^\/]*)\/([^\/]*).+$/;
  for (let client of clients) {
    debug('examining client', client.clientId);
    if (!client.clientId.match(idPattern) || client.disabled) {
      continue;
    }

    // when client has a github login, `patternMatch` will have an extra index entry with the user's GH username
    // e.g., ['mozilla-auth0/github%7c0000/helfi92, 'mozilla-auth0/github%7c0000', 'helfi92']
    const patternMatch = idPattern.exec(client.clientId);
    const clientIdentity = patternMatch[1];

    if (!user || user.identity !== patternMatch.slice(1).join('/')) {
      await Promise.all(Object
        .keys(cfg.handlers)
        .map(async h => {
          const handler = handlers[h];
          // remove the prefix and get the encoded user ID
          const encodedUserId = clientIdentity.split('/', 2)[1];

          user = await handler.userFromIdentity(
            decodeURIComponent(encodedUserId)
          );
        }));

      userScopes = (await auth.expandScopes({scopes: user.scopes()})).scopes;

      debug('..against user', user.identity);
    }

    // if this client's expandedScopes are not satisfied by the user's expanded
    // scopes, disable the client.
    if (!scopeUtils.scopeMatch(userScopes, [client.expandedScopes])) {
      await auth.disableClient(client.clientId);
    }
  }
}

module.exports = scanner;
