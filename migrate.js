const taskcluster = require('taskcluster-client');
const auth = new taskcluster.Auth();

const migrate = async () => {
  try {
    const roles = await auth.listRoles();

    // Migrate mozillians-unvouched
    await auth.createRole('everybody', {
      scopes: await auth.role('mozillians-unvouched').scopes,
      description: 'Role assigned to everybody. It should only have the scopes required to run the tutorial, and nothing that might harm other users of Taskcluster.',
    });

    roles
      .filter(({ roleId }) => roleId.startsWith('mozilla-user:'))
      .forEach(async ({roleId, scopes}) => {
        const email = roleId.replace('mozilla-user:', '');
        const emailPrefix = email.replace('@mozilla.com', '');

        if (email === '*') {
          // Migrate `mozilla-user:*`
          await auth.createRole('login-identity:*', {
            scopes,
            description: '',
          });
        } else {
          const identity = `mozilla-ldap/ad|Mozilla-LDAP|${emailPrefix}`;

          // Migrate `mozilla-user:${email}`
          await auth.createRole(`login-identity:${identity}`, {
            scopes,
            description: '',
          });
        }
      });
  } catch (err) {
    console.error(err);
  }
};

// 🚀
migrate();
