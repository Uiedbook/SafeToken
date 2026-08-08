# Security Audit

## The bad ones

### 1. Access tokens and refresh tokens are the same thing

`create()` doesn't put anything in the token that says what it is. The only difference between an access token and a refresh token is which time window you pass to `verify()`.

That means anyone holding an access token can just do:

```js
await Auth.verify(accessToken, "refresh");
```

and it works. So my "1 hour" access token is secretly a 1 month refresh token. That defeats the whole point of having two windows.

Fix: just enfore only one time window per instance safer. Remove the type.

### 2. The secret can be anything, even `"a"`

The constructor only checks the secret isn't empty:

```js
if (!init.secret) {
  throw new Error("Please provide safetoken secret");
}
```

Everything this library does hangs on the secret. If someone uses a weak one, an attacker only needs to see ONE token, then they can guess secrets on their own machine as fast as they want until the signature matches. No server involved, nothing to slow them down. Once they have the secret they can mint tokens for anyone.

Fix: require a minimum length. 32 characters at least. Refuse to start otherwise.

### 4. Expiry gets checked before the signature

In `verifyToken` the order is:

```js
if (!isIntime(timeWindow, time)) {
  throw new Error("Token expired");
}
// ... then signature check
```

So we make a decision based on data we haven't verified yet. The signature does cover the timestamp so nobody can fake it, but doing it in this order leaks info. An attacker can tell the difference between "this token is expired" and "this token is fake" from the error messages. Small thing, but free information is free information.

Fix: check the format, then the signature, then expiry. In that order.

## The smaller stuff

### 6. Timestamp wraps around in 2106

Only 4 bytes of the timestamp get stored. That overflows in year 2106 and starts from zero again. Mixed with the `Math.abs` bug, old tokens could become valid again when the timestamps line up. Not urgent, but worth knowing.

### 7. Payload gets parsed with zero checks

`verify()` and `decode()` just do `JSON.parse(...)` and hand back whatever is in there. A payload can contain `__proto__` and other fun keys. If someone downstream does `Object.assign(user, decoded)` with that, they have a prototype pollution problem. Should at least warn about it in the README.

### 8. `btoa` crashes on non-latin text

```js
btoa(JSON.stringify(payload))
```

If the payload has an emoji or Arabic or Chinese text, `btoa` throws. So `create()` blows up on perfectly normal user data. Need to UTF-8 encode with `TextEncoder` first, then base64 the bytes.

### 9. Errors leak internals

No try/catch anywhere. A malformed token makes `atob` or `JSON.parse` throw their raw errors to the caller. Should catch those and just throw one boring "Invalid token" error.

### 10. No way to rotate secrets

No key id, no version field. If the secret ever leaks, changing it kills every token instantly with no rollover period. Fine for now but should be documented so people know what they're signing up for.

### 11. String stack overflow with spread operator on large HMAC signatures (`String.fromCharCode(...uint8Array)`)

```js
const signature = base64UrlEncode(
  String.fromCharCode(...new Uint8Array(signatureBuffer))
);
```

Passing a `Uint8Array` directly to `String.fromCharCode(...arr)` via argument spreading can trigger `RangeError: Maximum call stack size exceeded` in V8 JavaScript engines if the byte array is large. While SHA-256 is 32 bytes (safe for current signature size), using spread syntax for byte array conversion is unsafe practice.

Fix: use `Buffer.from(signatureBuffer).toString('binary')` or `TextDecoder` / standard Uint8Array loop.

### 12. Non-standard timingSafeEqual loop fallback

```js
function timingSafeEqual(a: string, b: string): boolean {
  if (a?.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
```

Returning `false` immediately on length mismatch (`a?.length !== b.length`) leaks signature length over side-channel timing analysis. Standard timing-safe equality implementations always process a constant number of iterations regardless of length mismatch.

Fix: use Node's native `crypto.timingSafeEqual` or compare buffers with fixed loop length.

