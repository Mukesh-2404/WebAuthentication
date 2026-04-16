const express = require('express');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 4000;
const USERS = {}; // { username: { credentials: [...] } }
const CHALLENGES = {};

const rpID = 'Webauthentication.onrender.com';
const expectedOrigin = 'https://Webauthentication.onrender.com';

app.post('/register/start', async (req, res) => {
  const { username } = req.body;
  
  if (USERS[username]?.credentials?.length) {
    res.status(400).json({ message: 'User already exists' });
    return;
  }

  const options = await generateRegistrationOptions({
    rpName: 'WebAuthen',
    rpID,
    userID: username,
    userName: username,
    attestationType: 'none',
  });

  CHALLENGES[username] = options.challenge;
  res.send(options);
});

app.post('/register/finish', async (req, res) => {
  const { username, credential } = req.body;
  const challenge = CHALLENGES[username];

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
  const { credentialPublicKey, credentialID } = verification.registrationInfo;

  console.log("\n===== 🔑 PUBLIC KEY GENERATED =====");

  // Raw buffer
  console.log("Public Key (Buffer):", credentialPublicKey);

  // Convert to Base64 (readable)
  const publicKeyBase64 = Buffer.from(credentialPublicKey).toString("base64");
  console.log("Public Key (Base64):", publicKeyBase64);

  // Credential ID
  console.log("Credential ID:", Buffer.from(credentialID).toString("base64"));

  USERS[username] = {
    credentials: [{
      credentialID,
      credentialPublicKey,
      counter: verification.registrationInfo.counter,
      transports: verification.registrationInfo.transports,
    }],
  };
      delete CHALLENGES[username];
      console.log('✅ Registration successful:', username);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: '❌ Verification failed' });
    }
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/login/start', async (req, res) => {
  const { username } = req.body;
  const user = USERS[username];
  if (!user?.credentials?.length) {
    res.status(400).json({ error: 'User not found' });
    return;
  }

  const credential = user.credentials[0];
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [{
      id: credential.credentialID,
      type: 'public-key',
    }],
  });

  CHALLENGES[username] = options.challenge;
  res.send(options);
});

app.post('/login/finish', async (req, res) => {
  const { username, credential } = req.body;
  const user = USERS[username];
  const challenge = CHALLENGES[username];

  if (!user || !challenge) {
    res.status(400).json({ error: '❌ Invalid request' });
    return;
  }

  try {
    const dbCredential = user.credentials[0];
    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: dbCredential.credentialID,
        credentialPublicKey: dbCredential.credentialPublicKey,
        counter: dbCredential.counter,
      },
    });

    if (verification.verified) {
      dbCredential.counter = verification.authenticationInfo.newCounter;
      delete CHALLENGES[username];
      console.log('✅ Login successful:', username);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: '❌ Verification failed' });
    }
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/delete/start', async (req, res) => {
  const { username } = req.body;
  const user = USERS[username];

  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const credential = user.credentials[0];

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [{
      id: credential.credentialID,
      type: 'public-key',
    }],
  });

  CHALLENGES[username] = options.challenge;
  res.send(options);
});

app.post('/delete/finish', async (req, res) => {
  const { username, credential } = req.body;

  const user = USERS[username];
  const challenge = CHALLENGES[username];

  if (!user || !challenge) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  try {
    const dbCredential = user.credentials[0];

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: dbCredential.credentialID,
        credentialPublicKey: dbCredential.credentialPublicKey,
        counter: dbCredential.counter,
      },
    });

    if (verification.verified) {
      // ✅ DELETE USER ONLY AFTER SUCCESSFUL AUTH
      delete USERS[username];
      delete CHALLENGES[username];

      console.log('🗑️ Secure delete:', username);

      return res.json({ success: true });
    } else {
      return res.status(400).json({ error: 'Verification failed' });
    }

  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});