# PASETO for the Web Browser

[![Build Status](https://github.com/paragonie/paseto-browser.js/workflows/CI/badge.svg)](https://github.com/paragonie/paseto-browser.js/actions?workflow=CI)
[![npm version](https://img.shields.io/npm/v/paseto-browser.svg)](https://npm.im/paseto-browser)

This implements PASETO v4.local and v4.public in the browser, as well as
PASERK k4.seal.

## Why?

There are already other implementations of PASETO in JavaScript, but they're
intended for Node.js.

This implementation runs in a web browser (using TweetNaCl for the elliptic curve
operations).

## Installing

### NPM

```terminal
npm install paseto-browser
```

### For Web Browsers

Download the dist files from the GitHub releases, then embed them via `<script>` tags.

Please refer to the [examples](example) directory for more information.

## Usage

### PASETO

#### v4.local

```html
<script src="paseto.v4.local.js" type="module"></script>
<script type="module">
(async function () {
    // const encryptor = new PasetoV4Local(symmetric_key_uint8array)
    const encryptor = PasetoV4Local.generate()
    
    // You can now encode/decode tokens using encryptor
    const token = await encryptor.encode({'exp': "2039-01-01T13:37:00+00:00"})
    const decoded = await encryptor.decode(token)
    console.log(decoded.exp) // "2039-01-01T13:37:00+00:00"
})();
</script>
```

#### v4.public

```html
<script src="tweetnacl/nacl-fast.min.js" type="module"></script>
<script src="paseto-browser/paseto.v4.public.js" type="module"></script>
<script type="module">
(async function () {
    // const keypair = nacl.sign.keyPair()
    // const sk = keypair.secretKey
    // const pk = keypair.publicKey
    // const signer = new PasetoV4Public(pk, sk)
    const signer = PasetoV4Public.generate()
    // You can now encode/decode tokens using signer

    const token = await signer.encode({'exp': "2039-01-01T13:37:00+00:00"})
    const decoded = await signer.decode(token)
    console.log(decoded.exp) // "2039-01-01T13:37:00+00:00"
})();
</script>
```

### PASERK

#### k4.seal

```html
<script src="tweetnacl/nacl-fast.min.js" type="module"></script>
<script src="paseto-browser/paseto.v4.local.js" type="module"></script>
<script src="paseto-browser/paserk.k4.seal.js" type="module"></script>
<script type="module">
(async function () {
    const wrapper = PaserkK4Seal.generate()
    /// Alternative 1
    // const keypair = nacl.box.keyPair()
    // const sk = keypair.secretKey
    // const pk = keypair.publicKey
    // const test = new PaserkK4Seal(pk, sk)

    /// Alternative 2
    // const keypair = nacl.sign.keyPair()
    // const sk = keypair.secretKey
    // const pk = keypair.publicKey
    // const test = PaserkK4Seal.fromEdwardsKeys(pk, sk)

    // One-side (only needs pk)
    const p4l = PasetoV4Local.generate()
    const wrapped = await wrapper.wrap(p4l)
    const token = await p4l.encode({'exp': "2039-01-01T13:37:00+00:00"}, {'wpk': wrapped})
    
    // Other side (needs pk and sk), receives `token`
    const footer = PasetoV4Local.getFooter(token)
    const unwrapped = await test.unwrap(footer.wpk)
    const decoded = await unwrapped.decode(token)
    
    console.log(decoded.exp) // "2039-01-01T13:37:00+00:00"
})();
</script>
```

## Development / Contribution

To test your local changes, checkout this repository from Git then run the following commands:

```terminal
npm install
npm run build
```

### Note on `dist`

> **DO NOT** commit any changes to `dist`; we will rebuild from source.
> 
> Any pull requests that touch `dist` will not be accepted.
