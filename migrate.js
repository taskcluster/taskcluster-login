const taskcluster = require('taskcluster-client');
const auth = new taskcluster.Auth();

const migrate = async () => {
  try {
    const clients = await auth.listClients();

    // Migrate mozillians-unvouched
    await auth.createRole('everybody', {
      scopes: await auth.role('mozillians-unvouched'),
      description: 'Role assigned to everybody. It should only have the scopes required to run the tutorial, and nothing that might harm other users of Taskcluster.',
    });

    clients
      .filter(({clientId, disabled}) => clientId.startsWith('mozilla-ldap/') && !disabled)
      .forEach(async (client) => {
        const email = client.clientId.split('/', 2)[1];
        const emailPrefix = email.replace('@mozilla.com', '');

        try {
          const identity = `mozilla-ldap/ad|Mozilla-LDAP|${emailPrefix}`;

          // Migrate `mozilla-user:${email}`
          await auth.createRole(`login-identity:${identity}`, {
            scopes: await auth.role(`mozilla-user:${email}`),
            description: '',
          });
        } catch (err) {
          console.error(`role mozilla-user:${email} not found`);
        }
      });
  } catch (err) {
    console.error(err);
  }
};

// 🚀
migrate();
