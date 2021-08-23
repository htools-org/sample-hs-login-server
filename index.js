const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const { HandshakeLogin } = require('handshake-login');

const hLoginOptions = {
  useDoh: true,
  dohResolverUrl: 'https://easyhandshake.com:8053/dns-query',
};

const app = express();
const port = process.env.PORT || 3000;

app.use(
  session({
    resave: false,
    saveUninitialized: false,
    secret: 'very secret; much wow',
  })
);

// Template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Home page shows logged in domain from session (if any)
// Form is shown if no domain (in views/index.ejs)
app.get('/', (req, res) => {
  res.render('index', {
    domain: req.session.domain,
  });
});

// Login form is submitted as POST, contains only domain
app.post('/login', async function (req, res) {
  // New instance of HandshakeLogin every time.
  const hLogin = new HandshakeLogin(hLoginOptions);
  const domain = req.body.domain;

  // Generate a random challenge and store in session (to verify later)
  const randomValues = new Uint8Array(16);
  crypto.webcrypto.getRandomValues(randomValues);
  const challenge = Buffer.from(randomValues).toString('base64url');
  console.log('Generated challenge', challenge);
  req.session.challenge = challenge;

  // Generate Request URL and redirect to it (will be to an ID manager)
  // Set the callback to own website
  try {
    const requestUrl = await hLogin.generateRequestUrl({
      domain: domain,
      challenge: challenge,
      // callbackUrl: 'http://localhost:3000/callback',
      callbackUrl: req.protocol + '://' + req.get('host') + '/callback',
    });
    console.log('Request URL:', requestUrl);
    return res.redirect(requestUrl);
  } catch (error) {
    console.error(error);
    return res.status(500).send('Internal Error');
  }
});

// Data is returned in fragment, is not sent to server by browser.
// So serve an HTML file at callback that uses JavaScript to read the fragment
// and submit it as a query parameter.
// Example:
//    Callback url with data: http://localhost:3000/callback#eyJza...
//    JS submitted data: http://localhost:3000/servercallback?data=eyJza...
app.get('/callback', (req, res) => {
  res.render('callback');
});

// Read note for /callback.
app.get('/servercallback', async function (req, res) {
  const url =
    req.protocol +
    '://' +
    req.get('host') +
    req.originalUrl +
    '#' +
    req.query.data;

  try {
    // Create a new instance every time.
    const hLogin = new HandshakeLogin(hLoginOptions);

    // Parse response data
    const responseData = hLogin.parseResponseDataFromUrl(url);
    console.log('Response Data', responseData);

    // Verify everything (fingerprint with dns and public key,
    // signature with challenge and public key)
    const verified = await hLogin.verifyResponseData(req.session.challenge);
    console.log('verified:', verified);

    // If verified, store in session
    if (verified === true) {
      // Regenerate session when signing in
      // to prevent fixation
      req.session.regenerate(function () {
        // Store the user's primary key
        // in the session store to be retrieved,
        // or in this case the entire user object
        req.session.domain = responseData.domain;
        return res.redirect('/');
      });
    } else {
      // Couldn't log in
      return res.redirect('/');
    }
  } catch (error) {
    console.error(error);
    return res.status(500).send('Internal Error');
  }
});

// Destroy session on logout
app.get('/logout', (req, res) => {
  req.session.destroy(function () {
    res.redirect('/');
  });
});

// Start server
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
