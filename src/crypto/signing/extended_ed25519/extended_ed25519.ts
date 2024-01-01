/* eslint-disable @typescript-eslint/no-unused-vars */
import { Bip32Index, SoftIndex } from '../../../crypto/generation/bip32_index';
import { SHA512 } from '../../../crypto/hash/sha';
import { Ed25519Spec, PublicKey } from '../ed25519/ed25519_spec';
import { PointAccum, PointExt } from '../eddsa/ec';
import * as eddsa from '../eddsa/ed25519';
import { EllipticCurveSignatureScheme } from '../elliptic_curve_signature_scheme';
import { KeyPair } from '../signing';
import * as spec from './extended_ed25519_spec';

function fromLittleEndian(bytes: Uint8Array): bigint {
  let result = BigInt(0);
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

export function hexToUint8List(hex: string): Uint8Array {
  const hexString = hex.trim();
  const result = new Uint8Array(hexString.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }

  return result;
}

function uint8ListFromBytes(bytes: number[]): Uint8Array {
  return new Uint8Array(bytes);
}

function bigintToUint8Array(value: bigint): Uint8Array {
  const hexString = value.toString(16);
  const paddedHexString = hexString.length % 2 === 0 ? hexString : '0' + hexString;
  const byteArray = new Uint8Array(paddedHexString.length / 2);

  for (let i = 0; i < paddedHexString.length; i += 2) {
    byteArray[i / 2] = parseInt(paddedHexString.slice(i, i + 2), 16);
  }

  return byteArray;
}

function padArray(array: Uint8Array, length: number): Uint8Array {
  const paddedArray = new Uint8Array(length);
  paddedArray.set(array, 0);
  return paddedArray;
}

function getSublist(array: Uint8Array, start: number, end: number): Uint8Array {
  return array.slice(start, end);
}

export class ExtendedEd25519 extends EllipticCurveSignatureScheme<spec.SecretKey, spec.PublicKey> {
  public impl = new eddsa.Ed25519();

  constructor() {
    super(spec.ExtendedEd25519Spec.seedLength);
  }

  /// Sign a given message with a given signing key.
  ///
  /// Precondition: the private key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the signature must be a valid ExtendedEd25519 signature
  ///
  /// [privateKey] - The private signing key
  /// [message] - a message that the the signature will be generated for
  /// Returns the signature
  sign(privateKey: spec.SecretKey, message: Uint8Array): Uint8Array {
    const resultSig = new Uint8Array(spec.ExtendedEd25519Spec.signatureLength);
    const pk = new Uint8Array(spec.ExtendedEd25519Spec.publicKeyLength);
    const ctx = new Uint8Array(0);
    const phflag = 0x00;
    const leftKeyDataArray = privateKey.leftKey;
    const h = new Uint8Array([...leftKeyDataArray, ...privateKey.rightKey]);
    const s = leftKeyDataArray;
    const m = message;

    this.impl.scalarMultBaseEncoded(privateKey.leftKey, pk, 0);
    this.impl.implSignWithDigestAndPublicKey(new SHA512(), h, s, pk, 0, ctx, phflag, m, 0, m.length, resultSig, 0);

    return resultSig;
  }

  /// Verify a signature against a message using the public verification key.
  ///
  /// Precondition: the public key must be a valid Ed25519 public key
  /// Precondition: the signature must be a valid ExtendedEd25519 signature
  ///
  /// [signature] - the signature to use for verification
  /// [message] - the message that the signature is expected to verify
  /// [verifyKey] - The key to use for verification
  /// Returns true if the signature is verified; otherwise false.
  async verifyWithEd25519Pk(signature: Uint8Array, message: Uint8Array, verifyKey: PublicKey): Promise<boolean> {
    if (signature.length !== Ed25519Spec.signatureLength) {
      return false;
    }
    if (verifyKey.bytes.length !== Ed25519Spec.publicKeyLength) {
      return false;
    }

    return this.impl.verify({
      signature: signature,
      signatureOffset: 0,
      pk: verifyKey.bytes,
      pkOffset: 0,
      message: message,
      messageOffset: 0,
      messageLength: message.length,
    });
  }

  /// Verify a signature against a message using the public verification key.
  ///
  /// Precondition: the public key must be a valid ExtendedEd25519 public key
  /// Precondition: the signature must be a valid ExtendedEd25519 signature
  ///
  /// [signature] - the signature to use for verification
  /// [message] - the message that the signature is expected to verify
  /// [verifyKey] - The key to use for verification
  /// Returns true if the signature is verified; otherwise false.
  verify(signature: Uint8Array, message: Uint8Array, verifyKey: spec.PublicKey): boolean {
    if (signature.length != spec.ExtendedEd25519Spec.signatureLength) {
      return false;
    }
    if (verifyKey.vk.bytes.length != spec.ExtendedEd25519Spec.publicKeyLength) {
      return false;
    }

    return this.impl.verify({
      signature: signature,
      signatureOffset: 0,
      pk: verifyKey.vk.bytes,
      pkOffset: 0,
      message: message,
      messageOffset: 0,
      messageLength: message.length,
    });
  }

  /// Deterministically derives a child secret key located at the given index.
  ///
  /// Preconditions: the secret key must be a valid ExtendedEd25519 secret key
  /// Postconditions: the secret key must be a valid ExtendedEd25519 secret key
  ///
  /// The `secretKey` parameter is the secret key to derive the child key from.
  /// The `index` parameter is the index of the key to derive.
  ///
  /// Returns an extended secret key.
  deriveChildSecretKey(secretKey: spec.SecretKey, index: Bip32Index): spec.SecretKey {
    // Get the left and right numbers from the secret key
    const lNum = spec.ExtendedEd25519Spec.leftNumber(secretKey);
    const rNum = spec.ExtendedEd25519Spec.rightNumber(secretKey);

    // console.log('lNum -> ', rNum);

    // console.log('secret key -> ', secretKey);
    // console.log('index -> ', index);

    // Get the public key from the secret key
    const publicKey = this.getVerificationKey(secretKey);

    console.log('public -> ', index.bytes);

    // Construct the HMAC data for z
    // const zHmacData =
    //   index instanceof SoftIndex
    //     ? new Uint8Array([0x02, ...publicKey.vk.bytes, ...index.bytes])
    //     : new Uint8Array([0x00, ...secretKey.leftKey, ...secretKey.rightKey, ...index.bytes]);

    let zHmacData;

    if(index instanceof SoftIndex) {
      zHmacData = uint8ListFromBytes([0x02, ...publicKey.vk.bytes, ...index.bytes])
    } else {
      zHmacData = uint8ListFromBytes([0x00, ...secretKey.leftKey, ...secretKey.rightKey, ...index.bytes]);
    }

        // console.log('z -> ', zHmacData);
    // Compute z using HMAC-SHA-512 with the chain code as the key
    const z = spec.ExtendedEd25519Spec.hmac512WithKey(secretKey.chainCode, zHmacData);


    // Parse the left and right halves of z as big integers
    const zLeft = fromLittleEndian(z.slice(0, 28));
    const zRight = fromLittleEndian(z.slice(32, 64));

    // Compute the next left key by adding zLeft * 8 to the current left key
    const nextLeftBigInt = zLeft * BigInt(8) + lNum;
    const nextLeftPre = bigintToUint8Array(nextLeftBigInt);
    // console.log('next left pre -> ', nextLeftPre);
    const nextLeft = new Uint8Array(nextLeftPre.slice().reverse().slice(0, 32));

    // Compute the next right key by adding zRight to the current right key
    const nextRightBigInt = (zRight + rNum) % BigInt(2 ** 256);
    // const nextRightPre = new Uint8Array(
    //   BigInt.asUintN(256, nextRightBigInt)
    //     .toString(16)
    //     .match(/.{2}/g)!
    //     .map((byte) => parseInt(byte, 16)),
    // );
    const nextRightPre = bigintToUint8Array(nextRightBigInt)

    // console.log('next right pre -> ', nextRightPre);

    const nextRight = new Uint8Array(nextRightPre.slice().reverse().slice(0, 32));

    // Compute the next chain code using HMAC-SHA-512 with the chain code as the key
    const chaincodeHmacData =
      index instanceof SoftIndex
        ? new Uint8Array([0x03, ...publicKey.vk.bytes, ...index.bytes])
        : new Uint8Array([0x01, ...secretKey.leftKey, ...secretKey.rightKey, ...index.bytes]);

    const nextChainCode = spec.ExtendedEd25519Spec.hmac512WithKey(secretKey.chainCode, chaincodeHmacData).slice(32, 64);

    // console.log('next -> ', nextLeft);

    // Return the new secret key
    return new spec.SecretKey(nextLeft, nextRight, nextChainCode);
  }

  /// Derives a child public key located at the given soft index.
  ///
  /// This function follows section V.D from the BIP32-ED25519 spec.
  ///
  /// Returns:
  /// A new `PublicKey` object representing the derived child public key.
  deriveChildVerificationKey(verificationKey: spec.PublicKey, index: SoftIndex): spec.PublicKey {
    // console.log('xvk -> ', verificationKey);
    // console.log('index -> ', index);
    // Compute the HMAC-SHA-512 of the parent chain code
    const z = spec.ExtendedEd25519Spec.hmac512WithKey(
      verificationKey.chainCode,
      new Uint8Array([0x02, ...verificationKey.vk.bytes, ...index.bytes]),
    );

    // Extract the first 28 bytes of the HMAC-SHA-512 output as zL.
    const zL = z.slice(0, 28);
    
    // Multiply zL by 8 and convert the result to a little-endian byte array of length 8.
    const zLMult8BigInt = fromLittleEndian(zL) * BigInt(8);
    // console.log('z -> ', zLMult8BigInt);
    // const zLMult8Pre = new Uint8Array(
    //   BigInt.asUintN(256, zLMult8BigInt)
    //   .toString(16)
    //   .match(/.{2}/g)!
    //   .map((byte) => parseInt(byte, 16)),
    // );
    const zLMult8Pre = bigintToUint8Array(zLMult8BigInt);
    const zLMult8Rev = new Uint8Array(zLMult8Pre.reverse());
    // const zLMult8 = new Uint8Array(new Array(32).fill(0).concat(Array.from(zLMult8Rev).slice(0, 32)));
    const paddedArray = padArray(zLMult8Rev, 32);
    const zLMult8 = getSublist(paddedArray, 0, 32);
    // console.log('z -> ', zLMult8);

    // Compute the scalar multiplication of the base point by zL*8 to obtain scaledZL.
    const scaledZL = PointAccum.create();
    // console.log('scale -> ', zLMult8Bytes);
    this.impl.scalarMultBase(zLMult8, scaledZL);

    // console.log('scale -> ', zLMult8);
    // Decode the parent public key into a point and add scaledZL to it to obtain the next public key point.
    const publicKeyPoint = PointExt.create();
    this.impl.decodePointVar(verificationKey.vk.bytes, 0, { negate: false, r: publicKeyPoint });
    this.impl.pointAddVar1(false, publicKeyPoint, scaledZL);

    // Encode the next public key point as a byte array and compute the HMAC-SHA-512 of the parent chain code.
    const nextPublicKeyBytes = new Uint8Array(spec.ExtendedEd25519Spec.publicKeyLength);
    this.impl.encodePoint(scaledZL, nextPublicKeyBytes, 0);
    console.log('chain -> ', nextPublicKeyBytes);

    const nextChainCode = spec.ExtendedEd25519Spec.hmac512WithKey(
      verificationKey.chainCode,
      new Uint8Array([0x03, ...verificationKey.vk.bytes, ...index.bytes]),
    ).slice(32, 64);

    // Return the next public key and chain code as a PublicKey object.
    return new spec.PublicKey(new PublicKey(nextPublicKeyBytes), nextChainCode);
  }

  /// Get the public key from the secret key
  ///
  /// Precondition: the secret key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the public key must be a valid ExtendedEd25519 public key
  ///
  /// [secretKey] - the secret key
  /// Returns the public verification key
  getVerificationKey(secretKey: spec.SecretKey): spec.PublicKey {
    const pk = new Uint8Array(spec.ExtendedEd25519Spec.publicKeyLength);
    this.impl.scalarMultBaseEncoded(secretKey.leftKey, pk, 0);

    return new spec.PublicKey(new PublicKey(pk), secretKey.chainCode);
  }

  /// Derive an ExtendedEd25519 secret key from a seed.
  ///
  /// As defined in Section 3 of Khovratovich et. al. and detailed in CIP-0003, clamp bits to make a valid
  /// Bip32-Ed25519 private key
  ///
  /// Precondition: the seed must have a length of 96 bytes
  ///
  /// [seed] - the seed
  /// Returns the secret signing key
  deriveSecretKeyFromSeed(seed: Uint8Array): spec.SecretKey {
    if (seed.length !== spec.ExtendedEd25519Spec.seedLength) {
      throw new Error(
        `Invalid seed length. Expected: ${spec.ExtendedEd25519Spec.seedLength}, Received: ${seed.length}`,
      );
    }
    return spec.ExtendedEd25519Spec.clampBits(seed);
  }

  /// Deterministically derives a child secret key located at a given path of indices.
  ///
  /// Precondition: the secret key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the secret key must be a valid ExtendedEd25519 secret key
  ///
  /// [secretKey] - the secret key to derive the child key from
  /// [indices] - list of indices representing the path of the key to derive
  /// Returns an extended secret key
  deriveSecretKeyFromChildPath(secretKey: spec.SecretKey, indices: Bip32Index[]): spec.SecretKey {
    if (indices.length === 1) {
      return this.deriveChildSecretKey(secretKey, indices[0]);
    } else {
      return this.deriveSecretKeyFromChildPath(this.deriveChildSecretKey(secretKey, indices[0]), indices.slice(1));
    }
  }

  /// Deterministically derives a child key pair located at a given path of indices.
  ///
  /// Precondition: the secret key must be a valid ExtendedEd25519 secret key
  /// Postcondition: the key pair must be a valid ExtendedEd25519 key pair
  ///
  /// [secretKey] - the secret key to derive the child key pair from
  /// [indices] - list of indices representing the path of the key pair to derive
  /// Returns the key pair
  deriveKeyPairFromChildPath(
    secretKey: spec.SecretKey,
    indices: Bip32Index[],
  ): KeyPair<spec.SecretKey, spec.PublicKey> {
    const derivedSecretKey = this.deriveSecretKeyFromChildPath(secretKey, indices);
    const derivedPublicKey = this.getVerificationKey(derivedSecretKey);
    return new KeyPair(derivedSecretKey, derivedPublicKey);
  }
}

// export { PublicKey, SecretKey };
