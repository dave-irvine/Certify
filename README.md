# Certify


Create X.509 ASN.1 RSA Keypairs.

## Usage

```js
var Certify = require("certify");

var key = Certify();
console.log(key);
```

## Notes

Essentially a wrapper around the [Keypair](https://github.com/juliangruber/keypair) library, keypair wasn't providing the PublicKeyInfo section that the X.509 ASN.1 format requires.

## Installation

```bash
$ npm install certify
```

## Thanks

- [juliangruber](https://github.com/juliangruber/) for the [Keypair](https://github.com/juliangruber/keypair) library.
- [mcavage](https://github.com/mcavage/) for the [ASN.1](https://github.com/mcavage/node-asn1) library.
- [lapo-luchini](https://github.com/lapo-luchini/) for the [asn1js](https://github.com/lapo-luchini/asn1js) ASN.1 viewer.
- [asmblah](https://github.com/asmblah) for various brainwaves. 

## License

MIT