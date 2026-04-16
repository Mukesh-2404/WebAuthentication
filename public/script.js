const base64urlToBuffer = str => {
      const padding = '='.repeat((4 - str.length % 4) % 4);
      const base64 = (str + padding).replace(/-/g, '+').replace(/_/g, '/');
      const raw = atob(base64);
      return Uint8Array.from([...raw].map(c => c.charCodeAt(0))).buffer;
    };

    const bufferToBase64url = buf => {
      const bytes = new Uint8Array(buf);
      let binary = '';
      bytes.forEach(b => binary += String.fromCharCode(b));
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    };

    async function setStatus(text, isError = false) {
      const el = document.getElementById('status');
      el.textContent = text;
      el.className = isError ? 'error' : 'success';
    }

    async function register() {
      const username = document.getElementById('username').value.trim();
      if (!username) return setStatus('Enter username', true);

      try {
        setStatus('Starting registration...');
        const res = await fetch('/register/start', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username})
        });
        const options = await res.json();

        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);

        setStatus('Touch your security key / biometric...');
        const credential = await navigator.credentials.create({publicKey: options});

        const verification = {
          id: credential.id,
          rawId: bufferToBase64url(credential.rawId),
          type: credential.type,
          response: {
            attestationObject: bufferToBase64url(credential.response.attestationObject),
            clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          },
        };

        const verifyRes = await fetch('/register/finish', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username, credential: verification})
        });

        const result = await verifyRes.json();
        setStatus(result.success ? '✅ Registered!' : '❌ Registration failed', !result.success);
      } catch (err) {
        setStatus(`Error:${err.message}`, true);
      }
    }

    async function deleteUser() {
      const username = document.getElementById('username').value.trim();
      if (!username) return setStatus('Enter username', true);

      if (!confirm("Authenticate to delete your account")) return;

      try {
        setStatus('Verifying passkey for deletion...');

        // STEP 1: Start authentication
        const res = await fetch('/delete/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username })
        });

        const options = await res.json();

        options.challenge = base64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
          options.allowCredentials = options.allowCredentials.map(c => ({
            ...c,
            id: base64urlToBuffer(c.id)
          }));
        }

        // STEP 2: Ask for passkey
        const assertion = await navigator.credentials.get({ publicKey: options });

        const verification = {
          id: assertion.id,
          rawId: bufferToBase64url(assertion.rawId),
          type: assertion.type,
          response: {
            authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
            clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
            signature: bufferToBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle
              ? bufferToBase64url(assertion.response.userHandle)
              : undefined,
          },
        };

        // STEP 3: Send for verification + deletion
        const verifyRes = await fetch('/delete/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, credential: verification })
        });

        const result = await verifyRes.json();

        setStatus(
          result.success ? '🗑️ User deleted securely!' : result.error,
          !result.success
        );

      } catch (err) {
        setStatus(`Error: ${err.message}`, true);
      }
    }

    async function login() {
      const username = document.getElementById('username').value.trim();
      if (!username) return setStatus('Enter username', true);

      try {
        setStatus('Starting login...');
        const res = await fetch('/login/start', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username})
        });
        const options = await res.json();

        options.challenge = base64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
          options.allowCredentials = options.allowCredentials.map(c => ({
            ...c,
            id: base64urlToBuffer(c.id)
          }));
        }

        setStatus('Touch your security key / biometric...');
        const assertion = await navigator.credentials.get({publicKey: options});

        const verification = {
          id: assertion.id,
          rawId: bufferToBase64url(assertion.rawId),
          type: assertion.type,
          response: {
            authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
            clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
            signature: bufferToBase64url(assertion.response.signature),
            userHandle: assertion.response.userHandle ? 
              bufferToBase64url(assertion.response.userHandle) : undefined,
          },
        };

        const verifyRes = await fetch('/login/finish', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username, credential: verification})
        });

        const result = await verifyRes.json();
        setStatus(result.success ? '✅ Login successful!' : '❌ Login failed', !result.success);
      } catch (err) {
        setStatus(`Error: ${err.message}`, true);
      }
    }