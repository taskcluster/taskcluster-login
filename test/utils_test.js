const assume = require('assume');
const {encode, decode} = require('../src/utils');

suite('utils', function() {
  suite('encoding', () => {
    test('encode does not encode the pipe symbol', () => {
      const result = encode('ad|Mozilla-LDAP|haali');

      assume(result).to.equal('ad|Mozilla-LDAP|haali');
    });

    test('encode encodes % to !', () => {
      const result = encode('ad|Mozilla-LDAP|^haali^');

      assume(result).to.equal('ad|Mozilla-LDAP|!5Ehaali!5E');
    });
  });

  suite('decoding', () => {
    test('decode works with no special characters', () => {
      const str = 'ad|Mozilla-LDAP|haali';
      const encoded = encode(str);

      assume(decode(encoded)).to.equal(str);
    });

    test('decode works with special characters', () => {
      const str = 'ad|Mozilla-LDAP|^haali^';
      const encoded = encode(str);

      assume(decode(encoded)).to.equal(str);
    });
  });
});
