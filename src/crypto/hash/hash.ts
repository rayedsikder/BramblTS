import { Blake2b256, Blake2b512 } from './blake2B';
import { SHA256, SHA512 } from './sha';

const blake2b256 = new Blake2b256();
const blake2b512 = new Blake2b512();
const sha256 = new SHA256();
const sha512 = new SHA512();

export { blake2b256, blake2b512, sha256, sha512 };
