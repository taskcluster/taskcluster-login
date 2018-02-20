const ALLOWED_CHARACTERS_IN_CLIENT_ID = ['|'];

module.exports = {
  // the second capturing group is used to catch a user's github username
  CLIENT_ID_PATTERN: /^([^\/]*\/[^\/]*)\/([^\/]*).+$/,
  // Limits the encoding so that ALLOWED_CHARACTERS_IN_CLIENT_ID are not encoded
  encode: (str, allowed = ALLOWED_CHARACTERS_IN_CLIENT_ID) => {
    const encoded = allowed.reduce((acc, curr) => {
      const encodedSymbol = encodeURIComponent(curr);

      return acc.replace(new RegExp(encodedSymbol, 'g'), curr);
    }, encodeURIComponent(str));

    return encoded;
  },
};
