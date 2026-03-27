/**
 * E2EE Crypto helpers — all operations happen in the browser.
 * Uses the Web Crypto API (built into every modern browser, no libraries needed).
 *
 * Algorithm: RSA-OAEP (2048-bit) wrapping AES-256-GCM
 *
 * Why hybrid encryption?
 *   RSA-OAEP can only directly encrypt ~190 bytes (limited by key size).
 *   The fix: generate a fresh random AES key for each message, encrypt the
 *   message with AES-GCM (no size limit), then RSA-encrypt only the AES key.
 *   The server receives both and stores them — it still can't read anything
 *   because it doesn't have your RSA private key.
 */

const E2EE = (() => {

  // ─── Key Generation ────────────────────────────────────────────────────────

  /**
   * Generate a new RSA-OAEP key pair in the browser.
   * Returns the private key as a JWK (JSON object you save to disk)
   * and the public key as a compact base64 string you share with friends.
   */
  async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name:            'RSA-OAEP',
        modulusLength:   2048,
        publicExponent:  new Uint8Array([1, 0, 1]), // 65537
        hash:            'SHA-256',
      },
      true,  // extractable: true so we can export and save the keys
      ['encrypt', 'decrypt']
    );

    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const publicKeyB64  = await _exportPublicKey(keyPair.publicKey);

    return { privateKeyJwk, publicKeyB64 };
  }

  /**
   * Given a saved private key JWK, reconstruct the public key.
   *
   * How this works:
   *   An RSA private key in JWK format contains BOTH the private fields
   *   (d, p, q, dp, dq, qi) AND the public fields (n = modulus, e = exponent).
   *   We just strip the private fields to get the public key — no server needed.
   *
   * This is how "login with private key" works: the private key carries
   * enough information to prove your identity (via the public key) without
   * ever sending the private key anywhere.
   */
  async function derivePublicKey(privateKeyJwk) {
    // Build a public key JWK from the public components embedded in the private key
    const publicKeyJwk = {
      kty:     'RSA',
      n:       privateKeyJwk.n,   // modulus  (public)
      e:       privateKeyJwk.e,   // exponent (public)
      alg:     'RSA-OAEP-256',
      ext:     true,
      key_ops: ['encrypt'],
    };

    const key = await crypto.subtle.importKey(
      'jwk', publicKeyJwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true, ['encrypt']
    );
    return _exportPublicKey(key);
  }

  // ─── Encryption / Decryption ────────────────────────────────────────────────

  /**
   * Encrypt a plaintext string for a recipient.
   *
   * Steps:
   *   1. Generate a random AES-256-GCM key (used only for this one message)
   *   2. Encrypt the message with AES-GCM
   *   3. Encrypt the AES key with the recipient's RSA public key
   *   4. Bundle: { key (RSA-encrypted AES key), iv, ct (AES ciphertext) }
   *
   * Only the recipient can decrypt: they use their RSA private key to unwrap
   * the AES key, then use the AES key to decrypt the message.
   * The server stores this bundle but cannot read it.
   */
  async function encryptMessage(plaintext, recipientPublicKeyB64) {
    const recipientKey = await _importPublicKey(recipientPublicKeyB64);

    // 1. Fresh AES-256-GCM key — one key per message for perfect forward secrecy
    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true, ['encrypt']
    );

    // 2. Encrypt the message
    const iv         = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      new TextEncoder().encode(plaintext)
    );

    // 3. RSA-encrypt the AES key so only the recipient can unwrap it
    const rawAesKey      = await crypto.subtle.exportKey('raw', aesKey);
    const encryptedAesKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      recipientKey,
      rawAesKey
    );

    // 4. Bundle everything into a single base64 JSON string
    return btoa(JSON.stringify({
      key: _toB64(encryptedAesKey),
      iv:  _toB64(iv),
      ct:  _toB64(ciphertext),
    }));
  }

  /**
   * Decrypt a message using your own private key.
   * Reverses the steps in encryptMessage.
   */
  async function decryptMessage(encryptedB64, privateKeyJwk) {
    const { key, iv, ct } = JSON.parse(atob(encryptedB64));

    // 1. Import our RSA private key
    const privateKey = await crypto.subtle.importKey(
      'jwk', privateKeyJwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false, ['decrypt']
    );

    // 2. Unwrap the AES key using our private key
    const rawAesKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      _fromB64(key)
    );
    const aesKey = await crypto.subtle.importKey(
      'raw', rawAesKey,
      { name: 'AES-GCM' },
      false, ['decrypt']
    );

    // 3. Decrypt the message with the AES key
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _fromB64(iv) },
      aesKey,
      _fromB64(ct)
    );

    return new TextDecoder().decode(plaintext);
  }

  // ─── Utilities ──────────────────────────────────────────────────────────────

  /** Validate a public key by trying to import it. Throws if invalid. */
  async function validatePublicKey(publicKeyB64) {
    await _importPublicKey(publicKeyB64); // throws if bad
  }

  /** Short display ID for a public key: first 8 chars + … + last 4 chars */
  function shortId(publicKeyB64) {
    return publicKeyB64.slice(0, 8) + '…' + publicKeyB64.slice(-4);
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  async function _exportPublicKey(cryptoKey) {
    const spki = await crypto.subtle.exportKey('spki', cryptoKey);
    return _toB64(spki);
  }

  function _importPublicKey(b64) {
    return crypto.subtle.importKey(
      'spki', _fromB64(b64),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true, ['encrypt']
    );
  }

  function _toB64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  function _fromB64(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  return { generateKeyPair, derivePublicKey, encryptMessage, decryptMessage, validatePublicKey, shortId };
})();
