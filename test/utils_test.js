const assume = require('assume');
const {encode} = require('../src/utils');

suite('utils', function() {
  suite('encoding', () => {
    test('encode does not encode the pipe symbol', () => {
      const result = encode('ad|Mozilla-LDAP|^haali^');

      assume(result).to.equal('ad|Mozilla-LDAP|%5Ehaali%5E');
    });
  });
});
