/* eslint-disable @typescript-eslint/no-explicit-any */
import { BinaryToTextEncoding, createHmac } from 'crypto';
import Ed25519 from './crypto/signing/ed25519/ed25519';
import { SecretKey } from './crypto/signing/ed25519/ed25519_spec';

function uint8ArrayToHexString(uint8Array: Uint8Array): string {
  const hex = Buffer.from(uint8Array).toString('hex');
  return hex;
}

function stringToUint8Array(str: string): Uint8Array {
  const length = str.length / 2;
  const uint8Array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    const byteValue = parseInt(str.substr(i * 2, 2), 16);
    uint8Array[i] = byteValue;
  }

  return uint8Array;
}

const fromHexString = (hexString: any) =>
  Uint8Array.from(hexString.match(/.{1,2}/g).map((byte: any) => parseInt(byte, 16)));

const checkSign = new Ed25519().sign(
  new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
  stringToUint8Array(''),
);

class HMAC {
  private secretKey: string;
  private algorithm: string;

  constructor(secretKey: string, algorithm: string) {
    this.secretKey = secretKey;
    this.algorithm = algorithm;
  }

  compute(message: string, encoding: BinaryToTextEncoding = 'hex'): string {
    const hmac = createHmac(this.algorithm, this.secretKey);
    hmac.update(message);
    return hmac.digest(encoding);
  }
}

const hmac = new HMAC('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'sha512');

const checkHex = uint8ArrayToHexString(checkSign);

console.log(
  'checking signature',
  checkSign,
  checkHex,
  new SecretKey(stringToUint8Array('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')),
  hmac.compute('Hello world'),
);

console.log('from string...', fromHexString('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'));
