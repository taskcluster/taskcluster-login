const taskcluster = require('taskcluster-client');
const auth = new taskcluster.Auth();

const migrate = async () => {
  try {
    const roles = await auth.listRoles();

    // Migrate mozillians-unvouched
    await auth.createRole('everybody', {
      scopes: await (auth.role('mozillians-unvouched')).scopes,
      description: 'Role assigned to everybody. It should only have the scopes required to run the tutorial, and nothing that might harm other users of Taskcluster.',
    });

    const filteredRoles = roles.filter(({ roleId }) => roleId.startsWith('mozilla-user:') && roleId !== 'mozilla-user:*');

    for (let i = 0; i < filteredRoles.length; i++) {
      const { roleId, scopes, description } = filteredRoles[i];
      const emailPrefix = roleId
        .replace('mozilla-user:', '')
        .replace('@mozilla.com', '');
      const identity = `mozilla-ldap/ad|Mozilla-LDAP|${emailPrefix}`;

      try {
        // Migrate `mozilla-user:${email}`
        await auth.createRole(`login-identity:${identity}`, {
          scopes,
          description,
        });
      } catch (err) {
        console.error(err);
      }
    }
  } catch (err) {
    console.error(err);
  }
};

// 🚀
migrate();
