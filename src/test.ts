import { SHA512 } from './crypto/hash/sha';
import Ed25519 from './crypto/signing/ed25519/ed25519';
import { SecretKey } from './crypto/signing/ed25519/ed25519_spec';
// import { EC } from './crypto/signing/eddsa/ec';
// import fs from 'fs';

function stringToUint8Array(str: string): Uint8Array {
  const length = str.length / 2;
  const uint8Array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    const byteValue = parseInt(str.substr(i * 2, 2), 16);
    uint8Array[i] = byteValue;
  }

  return uint8Array;
}

// const checkSign = new Ed25519().sign(
//   new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
//   stringToUint8Array(''),
// );

// console.log('checking signature', checkSign);
// console.log('string', stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));

const publicKey = new Ed25519().getVerificationKey(
  new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
);
console.log('public key', publicKey.bytes);
// const buffer = Buffer.from(publicKey.bytes);
// console.log('public key', buffer.toString('hex'));

const sha512 = new SHA512();
const array = new Uint8Array(64);
const hash = sha512.hash(array);
console.log('hash1', hash);

// sha512.update(new Uint8Array([6, 7, 8, 9, 10]), 1, 3);
const hash2 = new Uint8Array(64);
sha512.doFinal(hash2, 0);
console.log('hash2', hash2);

// const thirdParam = fs.readFileSync('new.json', 'utf8');
// const thirdParamParse = JSON.parse(thirdParam);

// console.log('third...', thirdParamParse);


// const newCmov = new EC();
// console.log('new log', newCmov.cmov(1, 0, [1, 2, 3, 4, 5], 0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0))