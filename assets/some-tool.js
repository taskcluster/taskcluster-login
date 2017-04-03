var DOMAIN = "auth-dev.mozilla.auth0.com";
var CLIENT_ID = "AKWT8X3N1Qm4YyG6zQjfM22Fo6mblkhv";
var forcePrompt;
var authorizeError = undefined;
var idToken, accessToken, step;
var creds, credsError;

function step_start(status) {
  var prompt;
  if (authorizeError && (authorizeError.error === 'login_required' || authorizeError.error === 'consent_required' || authorizeError.error === 'interaction_required')) {
    prompt = "login";
  } else if (forcePrompt) {
    prompt = "login";
  } else {
    prompt = "none";
  }

  var auth_url = "https://" + DOMAIN + "/authorize";
  auth_url = auth_url + "?audience=taskcluster-login.ngrok.io";
  auth_url = auth_url + "&scope=get-credentials openid profile";
  auth_url = auth_url + "&response_type=token id_token";
  auth_url = auth_url + "&client_id=" + CLIENT_ID,
  auth_url = auth_url + "&redirect_uri=https://taskcluster-login.ngrok.io/some-tool";
  auth_url = auth_url + "&state=STATE";
  auth_url = auth_url + "&nonce=NONCE";
  auth_url = auth_url + "&prompt=" + prompt;
  var auth_url_newlines = auth_url.replace(/([?&])/g, '<br>\n&nbsp$1');
  rv =  [
    '<p>',
    'The client uses an /authorize link that includes an <tt>audience</tt> field pointing to the tc-login API. ',
  ];
  rv.push('Here is the link:<br />');
  rv.push('<a href="' + auth_url + '">' + auth_url_newlines + '</a>');
  rv.push('</p>');
  if (prompt === 'login' && authorizeError) {
    rv.push('<p><tt>prompt</tt> has been set to <tt>login</tt> because auth0 replied with <tt>error=' + authorizeError.error + '</tt>.');
    rv.push('Click again (a real client would not stop to wait for a click but just call the authorize endpoint again).');
  } else {
    rv.push('<p>The <tt>prompt=none</tt> means that if you are already logged in, Auth0 will redirect back here immediately.');
    rv.push('<a href="#" onClick="forcePrompt = !forcePrompt; showSteps()">Toggle <tt>prompt</tt></a></p>');
  }
  if (status === 'current' && idToken) {
    rv.push('<br/><button type="submit" onClick="gotoStep(\'auth0-returns-tokens\')">Next</button>');
  }
  rv.push('</p>');
  return rv;
}

function step_auth0_returns_tokens(status) {
  if (status === 'pending') {
    return [];
  }

  var rv = [];
  var showToken = function(token) {
    var text = '(none)';
    if (token) {
      try {
        var decoded = jwt_decode(token);
        text = JSON.stringify(decoded, null, 2);
      } catch (e) {
        text = token + "\n" + "error decoding: " + e;
      }
    }
    rv.push(text);
  };

  rv.push('<p>Got ID token JWT:<pre>');
  showToken(idToken);
  rv.push('</pre>..and access token JWT:<pre>');
  showToken(accessToken);
  rv.push('</pre>');
  rv.push('Some-tool can use the ID token to identify the user, via the `/userinfo` endpoint if necessary - this is the normal auth0/OIDC login flow. The access token is for use connecting to the tc-login API.');
  if (status === 'current') {
    rv.push('<br/><button type="submit" onClick="gotoStep(\'client-gets-credentials\')">Next</button>');
  }
  rv.push('</p>');

  return rv;
}

function step_client_gets_credentials(status) {
  if (status === 'pending') {
    return [];
  }

  var rv = [];
  rv.push('<p>The credentials endpoint:<ul>');
  rv.push('<li>Validates the access token JWT.');
  rv.push('<li>Calls the <a href="https://auth0.com/docs/api/management/v2">Auth0 Management API</a>\'s get_users_by_id endpoint, passing the `sub` from the access token.');
  if (creds) {
    rv.push('Result:<pre>' + JSON.stringify(creds.profile, null, 2) + '</pre>');
  } else if (credsError) {
    rv.push('Error:<pre>' + credsError + '</pre>');
  }
  rv.push('<li>Based on the user profile, creates TaskCluster temporary credentials.');
  if (creds) {
    rv.push('Result:<pre>' + JSON.stringify(creds.credentials, null, 2) + '</pre>');
  }
  rv.push('</ul>')
  rv.push('<button type="submit" onClick="getCredentials()">Get Credentials</button>');
  if (status === 'current' && creds) {
    rv.push('<br/><button type="submit" onClick="gotoStep(\'client-uses-credentials\')">Next</button>');
  }
  rv.push('</p>');
  return rv;
}

function getCredentials() {
  var req = new XMLHttpRequest();
  req.open('GET', '/creds', false);
  req.setRequestHeader('Authorization', 'Bearer ' + accessToken);
  req.send(null);
  if (req.status === 200) {
    creds = JSON.parse(req.responseText);
    credsError = undefined;
  } else {
    creds = undefined;
    credsError = req.responseText;
  }
  showSteps();
}

var STEPS = [
  {name: 'start', description: 'Some-tool sends the user to the /authorize endpoint to sign in', body: step_start},
  {name: 'auth0-returns-tokens', description: 'Auth0 returns id_token and access_token to some-tool', body: step_auth0_returns_tokens},
  {name: 'client-gets-credentials', description: 'Some-tool calls the Login API credentials endpoint, using the returned access token', body: step_client_gets_credentials},
  {name: 'client-uses-credentials', description: 'Some-tool calls a Taskcluster API using the returned TC credentials'},
];

function gotoStep(newStep) {
  step = newStep;
  showSteps();
}

var showSteps = function() {
  var stepHTML = [];
  var status = 'done';
  STEPS.forEach(function(st) {
    stepHTML.push('<li>');
    if (step === st.name) {
      status = 'current';
      stepHTML.push('<em>' + st.description + '</em>');
    } else {
      if (status === 'current') {
        status = 'pending';
      }
      stepHTML.push(st.description);
    }
    if (st.body) {
      stepHTML = stepHTML.concat(st.body(status));
    }
    stepHTML.push('</li>');
  });
  document.getElementById('steps').innerHTML = stepHTML.join('\n');
}

function handlePageLoad() {
  var getParameterByName = function(name) {
    var match = RegExp('[#&]' + name + '=([^&]*)').exec(window.location.hash);
    return match && decodeURIComponent(match[1].replace(/\+/g, ' '));
  };

  var error = getParameterByName('error');
  if (error) {
    authorizeError = {error: error, error_description: getParameterByName('error_description')};
    console.log(authorizeError);
  } else {
    idToken = getParameterByName('id_token');
    accessToken = getParameterByName('access_token');
  }

  if (idToken) {
    step = 'auth0-returns-tokens';
  } else {
    step = 'start';
  }

  showSteps();
}

handlePageLoad();
