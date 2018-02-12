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

  const clients = await auth.listClients();

  // iterate through the clients, constructing a new User as necessary, comparing
  // the client's scopes to the User's scopes and disabling where necessary.
  let user, userScopes;
  let idPattern = /^([^\/]*\/[^\/]*)\/.+$/;
  for (let client of clients) {
    debug('examining client', client.clientId);
    if (!client.clientId.match(idPattern) || client.disabled) {
      continue;
    }

    // refresh the user if it does not correspond to this client
    let urlEncodedIdentity = client.clientId.replace(idPattern, '$1');

    if (!user || user.identity != urlEncodedIdentity) {
      await Promise.all(Object
        .keys(cfg.handlers)
        .map(async h => {
          const handler = handlers[h];
          const identity = urlEncodedIdentity.split('/', 2)[1];
          const cleanIdentity = identity.startsWith('github') ?
            identity.substr(0, identity.lastIndexOf(encodeURIComponent('|'))) :
            identity;

          user = await handler.userFromIdentity(cleanIdentity);
        }));

      userScopes = (await auth.expandScopes({scopes: user.scopes()})).scopes;
      // allow the implicit 'assume:client-id:<urlencodedUserId> auth adds for each client
      userScopes.push('assume:client-id:' + urlEncodedIdentity + '/*');

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
