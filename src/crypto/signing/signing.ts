// abstract class SigningKey {}

// abstract class VerificationKey {}

import * as spec from '../../../proto/quivr/models/shared'

export class KeyPair<SK extends spec.quivr.models.SigningKey, VK extends spec.quivr.models.VerificationKey> {
  signingKey: SK;
  verificationKey: VK;

  constructor(signingKey: SK, verificationKey: VK) {
    this.signingKey = signingKey;
    this.verificationKey = verificationKey;
  }

  equals(other: KeyPair<SK, VK>): boolean {
    return (
      this.signingKey === other.signingKey &&
      this.verificationKey === other.verificationKey
    );
  }

  hashCode(): number {
    return this.signingKey.hashCode() ^ this.verificationKey.hashCode();
  }
}
