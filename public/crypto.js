/**
 * E2EE Crypto helpers — all operations happen in the browser.
 * Uses the Web Crypto API (built into every modern browser).
 *
 * Algorithm: ECDH P-256 + HKDF-SHA256 + AES-256-GCM
 *
 * Key format:
 *   Private key → 32 bytes shown as 64 hex characters (like an Ethereum key)
 *   Public key  → ECDH P-256 public point in base64-SPKI format (share this with friends)
 *
 * Why ECDH instead of RSA?
 *   - Private key is 32 bytes (clean hex), not a giant JSON blob
 *   - Public key is ~124 chars base64, not ~400 chars
 *   - ECDH produces a shared secret: ECDH(Alice_priv, Bob_pub) = ECDH(Bob_priv, Alice_pub)
 *     This means both parties can decrypt all messages in a conversation — including
 *     their own sent messages — using just their own private key + the contact's public key.
 *
 * Encryption per message:
 *   1. ECDH(myPrivate, theirPublic) → 32-byte shared secret
 *   2. HKDF(sharedSecret, randomSalt) → 256-bit AES key  (different key per message)
 *   3. AES-256-GCM encrypt with random IV
 *   Server stores { salt, iv, ciphertext } — it cannot read any of it.
 */

const E2EE = (() => {

  // ─────────────────────────────────────────────────────────────────────────────
  // P-256 elliptic curve constants & scalar multiplication
  //
  // We need this so users can log in by typing their 64-char hex private key.
  // Web Crypto can't derive a public key from just the private scalar — it needs
  // the (x, y) point too. So we compute the public key ourselves via EC math.
  //
  // Security note: this is not constant-time (timing attacks possible), which is
  // fine for a learning app. Production implementations use constant-time routines.
  // ─────────────────────────────────────────────────────────────────────────────

  const _P  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const _A  = _P - 3n; // -3 mod P (P-256 uses a = -3)
  const _Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
  const _Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

  // Reduce x to [0, P)
  function _mod(x) { return ((x % _P) + _P) % _P; }

  // Modular inverse via extended Euclidean algorithm
  function _modInv(a) {
    a = _mod(a);
    let [r0, r1] = [_P, a];
    let [s0, s1] = [0n, 1n];
    while (r1 !== 0n) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [s0, s1] = [s1, s0 - q * s1];
    }
    return _mod(s0); // s0 satisfies: a * s0 ≡ 1 (mod P)
  }

  // Add two EC points (or double if they are the same point)
  function _pointAdd(P1, P2) {
    if (P1 === null) return P2;
    if (P2 === null) return P1;
    const [x1, y1] = P1;
    const [x2, y2] = P2;

    let m;
    if (x1 === x2) {
      if (y1 !== y2) return null; // P + (-P) = point at infinity
      // Point doubling: tangent slope m = (3x² + a) / (2y)
      m = _mod(_mod(3n * x1 * x1 + _A) * _modInv(2n * y1));
    } else {
      // Chord slope: m = (y2 - y1) / (x2 - x1)
      m = _mod(_mod(y2 - y1) * _modInv(x2 - x1));
    }

    const x3 = _mod(m * m - x1 - x2);
    const y3 = _mod(m * (x1 - x3) - y1);
    return [x3, y3];
  }

  // Scalar multiplication: returns k * point using double-and-add
  function _scalarMult(k, point) {
    let result = null; // identity (point at infinity)
    let addend = point;
    while (k > 0n) {
      if (k & 1n) result = _pointAdd(result, addend);
      addend = _pointAdd(addend, addend);
      k >>= 1n;
    }
    return result;
  }

  // ─── Key Generation ────────────────────────────────────────────────────────

  /**
   * Generate a new ECDH P-256 key pair.
   * Returns:
   *   privateHex — 64 hex chars, the key the user saves (like an Ethereum private key)
   *   publicB64  — base64 SPKI string, share this with friends so they can message you
   */
  async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );

    // Extract private scalar 'd' from JWK and convert to hex
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    const privateHex  = _bytesToHex(_b64urlToBytes(privateJwk.d));

    // Export public key as compact SPKI base64
    const spki       = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const publicB64  = _bytesToB64(spki);

    return { privateHex, publicB64 };
  }

  /**
   * Given a 64-char hex private key, compute the P-256 public key and
   * return CryptoKey objects ready for ECDH operations.
   *
   * This is how "login with hex" works:
   *   1. Treat the hex as the private scalar d
   *   2. Compute the public key point = d * G (EC scalar multiplication)
   *   3. Import both into Web Crypto
   */
  async function importFromHex(privateHex) {
    privateHex = privateHex.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(privateHex)) {
      throw new Error('Private key must be exactly 64 hex characters (32 bytes).');
    }

    const d = BigInt('0x' + privateHex);

    // Compute public key point: P = d * G
    const [px, py] = _scalarMult(d, [_Gx, _Gy]);

    // Build public key JWK from the (x, y) coordinates
    const publicJwk = {
      kty: 'EC', crv: 'P-256',
      x: _bytesToB64url(_bigintToBytes(px)),
      y: _bytesToB64url(_bigintToBytes(py)),
      ext: true, key_ops: [],
    };

    // Import public key and export as SPKI base64
    const publicCryptoKey = await crypto.subtle.importKey(
      'jwk', publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true, []
    );
    const spki      = await crypto.subtle.exportKey('spki', publicCryptoKey);
    const publicB64 = _bytesToB64(spki);

    // Build private key JWK — Web Crypto requires (d, x, y) together
    const privateJwk = {
      kty: 'EC', crv: 'P-256',
      d: _bytesToB64url(_hexToBytes(privateHex)),
      x: publicJwk.x,
      y: publicJwk.y,
      ext: true, key_ops: ['deriveKey', 'deriveBits'],
    };

    const privateCryptoKey = await crypto.subtle.importKey(
      'jwk', privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false, ['deriveKey', 'deriveBits']
    );

    return { privateCryptoKey, publicCryptoKey, publicB64 };
  }

  // ─── Encryption / Decryption ────────────────────────────────────────────────

  /**
   * Encrypt a message to send to a contact.
   *
   * How it works:
   *   ECDH(myPrivate, theirPublic) → shared secret (only these two users can compute it)
   *   HKDF(sharedSecret, randomSalt) → per-message AES-256 key
   *   AES-GCM(plaintext) → ciphertext
   *
   * The random salt means a different AES key is used for every message,
   * even though the ECDH shared secret is static.
   */
  async function encryptMessage(plaintext, myPrivateCryptoKey, theirPublicB64) {
    const theirKey = await _importPublicKey(theirPublicB64);

    // ECDH → raw shared secret bits
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: theirKey },
      myPrivateCryptoKey,
      256
    );

    // HKDF with a fresh random salt → unique AES key for this message
    const salt   = crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await _deriveAESKey(sharedBits, salt, 'encrypt');

    // AES-GCM encrypt
    const iv         = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      new TextEncoder().encode(plaintext)
    );

    return btoa(JSON.stringify({
      salt: _bytesToB64(salt),
      iv:   _bytesToB64(iv),
      ct:   _bytesToB64(ciphertext),
    }));
  }

  /**
   * Decrypt a message using your private key and the sender's public key.
   *
   * Works for BOTH received messages (from them → you) AND your own sent messages,
   * because the ECDH shared secret is symmetric:
   *   ECDH(Alice_priv, Bob_pub) == ECDH(Bob_priv, Alice_pub)
   */
  async function decryptMessage(encryptedB64, myPrivateCryptoKey, theirPublicB64) {
    const { salt, iv, ct } = JSON.parse(atob(encryptedB64));
    const theirKey = await _importPublicKey(theirPublicB64);

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: theirKey },
      myPrivateCryptoKey,
      256
    );

    const aesKey = await _deriveAESKey(sharedBits, _b64ToBytes(salt), 'decrypt');

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: _b64ToBytes(iv) },
      aesKey,
      _b64ToBytes(ct)
    );

    return new TextDecoder().decode(plaintext);
  }

  // ─── Helpers ────────────────────────────────────────────────────────────────

  /** Validate a public key. Throws if the base64 SPKI string is invalid. */
  async function validatePublicKey(publicB64) {
    await _importPublicKey(publicB64);
  }

  /** Short display string for a public key: first 8 + … + last 4 chars */
  function shortId(publicB64) {
    return publicB64.slice(0, 8) + '…' + publicB64.slice(-4);
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  async function _deriveAESKey(sharedBits, salt, usage) {
    const hkdfKey = await crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: new TextEncoder().encode('chat-e2ee-v1'),
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false, [usage]
    );
  }

  function _importPublicKey(b64) {
    return crypto.subtle.importKey(
      'spki', _b64ToBytes(b64),
      { name: 'ECDH', namedCurve: 'P-256' },
      true, []
    );
  }

  // BigInt (256-bit) → 32-byte Uint8Array (big-endian, zero-padded)
  function _bigintToBytes(n) {
    const hex = n.toString(16).padStart(64, '0');
    return _hexToBytes(hex);
  }

  function _hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  function _bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Standard base64 (for SPKI, ciphertext transport)
  function _bytesToB64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function _b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  // Base64url (no padding, for JWK fields like d, x, y)
  function _bytesToB64url(bytes) {
    return btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function _b64urlToBytes(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - b64.length % 4) % 4;
    return Uint8Array.from(atob(b64 + '='.repeat(pad)), c => c.charCodeAt(0));
  }

  return {
    generateKeyPair,
    importFromHex,
    encryptMessage,
    decryptMessage,
    validatePublicKey,
    shortId,
  };
})();
