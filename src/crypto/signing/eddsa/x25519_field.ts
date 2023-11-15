import { toByte } from './ec';

/* eslint-disable @typescript-eslint/no-unused-vars */
export const SIZE = 10;
export const M24 = 0x00ffffff;
export const M25 = 0x01ffffff;
export const M26 = 0x03ffffff;
export const ROOT_NEG_ONE = Int32Array.from([
  0x020ea0b0, 0x0386c9d2, 0x00478c4e, 0x0035697f, 0x005e8630, 0x01fbd7a7, 0x0340264f, 0x01f0b2b4, 0x00027e0e,
  0x00570649,
]);

export function add(x: Int32Array, y: Int32Array, z: Int32Array): void {
  for (let i = 0; i < SIZE; i++) {
    z[i] = x[i] + y[i];
  }
}

export function addOne1(z: Int32Array): void {
  z[0] += 1;
}

export function addOne2(z: Int32Array, zOff: number): void {
  z[zOff] += 1;
}

export function apm(x: Int32Array, y: Int32Array, zp: Int32Array, zm: Int32Array): void {
  for (let i = 0; i < SIZE; i++) {
    const xi = x[i];
    const yi = y[i];
    zp[i] = Number(xi + yi);
    zm[i] = Number(xi - yi);
  }
}

export function carry(z: Int32Array) {
  let z0 = z[0],
    z1 = z[1],
    z2 = z[2],
    z3 = z[3],
    z4 = z[4],
    z5 = z[5],
    z6 = z[6],
    z7 = z[7],
    z8 = z[8],
    z9 = z[9];

  z3 += z2 >> 25;
  z2 &= M25;
  z5 += z4 >> 25;
  z4 &= M25;
  z8 += z7 >> 25;
  z7 &= M25;
  z0 += (z9 >> 25) * 38;
  z9 &= M25;
  z1 += z0 >> 26;
  z0 &= M26;
  z6 += z5 >> 26;
  z5 &= M26;
  z2 += z1 >> 26;
  z1 &= M26;
  z4 += z3 >> 26;
  z3 &= M26;
  z7 += z6 >> 26;
  z6 &= M26;
  z9 += z8 >> 26;
  z8 &= M26;

  z[0] = z0;
  z[1] = z1;
  z[2] = z2;
  z[3] = z3;
  z[4] = z4;
  z[5] = z5;
  z[6] = z6;
  z[7] = z7;
  z[8] = z8;
  z[9] = z9;
}

export function cmov(cond: number, x: Int32Array, xOff: number, z: Int32Array, zOff: number) {
  for (let i = 0; i < SIZE; i++) {
    let z_i = z[zOff + i];
    const diff = z_i ^ x[xOff + i];
    z_i ^= diff & cond;
    z[zOff + i] = z_i;
  }
}

export function cnegate(negate: number, z: Int32Array) {
  const mask = Number(0 - negate);

  for (let i = 0; i < SIZE; i++) {
    z[i] = Number((z[i] ^ mask) - mask);
  }
}

export function copy(x: Int32Array, xOff: number, z: Int32Array, zOff: number) {
  for (let i = 0; i < SIZE; i++) {
    z[zOff + i] = x[xOff + i];
  }
}

export function cswap(swap: number, a: Int32Array, b: Int32Array) {
  const mask = 0 - swap;

  for (let i = 0; i < SIZE; i++) {
    const ai = a[i];
    const bi = b[i];
    const dummy = mask & (ai ^ bi);
    a[i] = Number(ai ^ dummy);
    b[i] = Number(bi ^ dummy);
  }
}

export function create(): Int32Array {
  return new Int32Array(SIZE);
}

export function decode(x: Uint8Array, xOff: number, z: Int32Array): void {
  decode128(x, xOff, z, 0);
  decode128(x, xOff + 16, z, 5);
  z[9] = Number(z[9] & M24);
}

export function decode128(bs: Uint8Array, off: number, z: Int32Array, zOff: number): void {
  const t0 = decode32(bs, off + 0);
  const t1 = decode32(bs, off + 4);
  const t2 = decode32(bs, off + 8);
  const t3 = decode32(bs, off + 12);

  z[zOff + 0] = Number(t0 & M26);
  z[zOff + 1] = Number(((t1 << 6) | (t0 >>> 26)) & M26);
  z[zOff + 2] = Number(((t2 << 12) | (t1 >>> 20)) & M25);
  z[zOff + 3] = Number(((t3 << 19) | (t2 >>> 13)) & M26);
  z[zOff + 4] = Number(t3 >>> 7);
}

export function decode32(bs: Uint8Array, off: number): number {
  let n = bs[off] & 0xff;
  n |= (bs[off + 1] & 0xff) << 8;
  n |= (bs[off + 2] & 0xff) << 16;
  n |= (bs[off + 3] & 0xff) << 24;
  return n;
}

export function encode(x: Int32Array, z: Uint8Array, zOff: number): void {
  encode128(x, 0, z, zOff);
  encode128(x, 5, z, zOff + 16);
}

export function encode128(x: Int32Array, xOff: number, bs: Uint8Array, off: number): void {
  const x0 = x[xOff + 0];
  const x1 = x[xOff + 1];
  const x2 = x[xOff + 2];
  const x3 = x[xOff + 3];
  const x4 = x[xOff + 4];

  const t0 = x0 | (x1 << 26);
  encode32(t0, bs, off + 0);

  const t1 = (x1 >>> 6) | (x2 << 20);
  encode32(t1, bs, off + 4);

  const t2 = (x2 >>> 12) | (x3 << 13);
  encode32(t2, bs, off + 8);

  const t3 = (x3 >>> 19) | (x4 << 7);
  encode32(t3, bs, off + 12);
}

export function encode32(n: number, bs: Uint8Array, off: number): void {
  bs[off + 0] = n & 0xff;
  bs[off + 1] = toByte(n >>> 8);
  bs[off + 2] = toByte(n >>> 16);
  bs[off + 3] = toByte(n >>> 24);
}

export function inv(x: Int32Array, z: Int32Array): void {
  const x2 = create();
  const t = create();

  powPm5d8(x, x2, t);
  sqr2(t, 3, t);
  mul2(t, x2, z);
}

export function isZero(x: Int32Array): number {
  let d = 0;

  for (let i = 0; i < SIZE; i++) {
    d |= x[i];
  }

  d = (d >>> 1) | (d & 1);

  return (d - 1) >> 31;
}

export function isZeroVar(x: Int32Array): boolean {
  return isZero(x) !== 0;
}

export function mul1(x: Int32Array, y: number, z: Int32Array) {
  const x0 = x[0];
  const x1 = x[1];
  let x2 = x[2];
  const x3 = x[3];
  let x4 = x[4];
  const x5 = x[5];
  const x6 = x[6];
  let x7 = x[7];
  const x8 = x[8];
  let x9 = x[9];

  let c0 = BigInt(0);
  let c1 = BigInt(0);
  let c2 = BigInt(0);
  let c3 = BigInt(0);

  c0 = BigInt(x2) * BigInt(y);
  x2 = Number(c0) & M25;
  c0 >>= BigInt(25);

  c1 = BigInt(x4) * BigInt(y);
  x4 = Number(c1) & M25;
  c1 >>= BigInt(25);

  c2 = BigInt(x7) * BigInt(y);
  x7 = Number(c2) & M25;
  c2 >>= BigInt(25);

  c3 = BigInt(x9) * BigInt(y);
  x9 = Number(c3) & M25;
  c3 >>= BigInt(25);

  c3 *= BigInt(38);
  c3 += BigInt(x0) * BigInt(y);
  z[0] = Number(c3) & M26;
  c3 >>= BigInt(26);

  c1 += BigInt(x5) * BigInt(y);
  z[5] = Number(c1) & M26;
  c1 >>= BigInt(26);

  c3 += BigInt(x1) * BigInt(y);
  z[1] = Number(c3) & M26;
  c3 >>= BigInt(26);

  c0 += BigInt(x3) * BigInt(y);
  z[3] = Number(c0) & M26;
  c0 >>= BigInt(26);

  c1 += BigInt(x6) * BigInt(y);
  z[6] = Number(c1) & M26;
  c1 >>= BigInt(26);

  c2 += BigInt(x8) * BigInt(y);
  z[8] = Number(c2) & M26;
  c2 >>= BigInt(26);

  z[2] = x2 + Number(c3);
  z[4] = x4 + Number(c0);
  z[7] = x7 + Number(c1);
  z[9] = x9 + Number(c2);
}

export function mul2(x: Int32Array, y: Int32Array, z: Int32Array) {
  const M25 = BigInt(0x01ffffff);
  const M26 = BigInt(0x03ffffff);

  let x0 = x[0];
  let y0 = y[0];
  let x1 = x[1];
  let y1 = y[1];
  let x2 = x[2];
  let y2 = y[2];
  let x3 = x[3];
  let y3 = y[3];
  let x4 = x[4];
  let y4 = y[4];

  const u0 = x[5];
  const v0 = y[5];
  const u1 = x[6];
  const v1 = y[6];
  const u2 = x[7];
  const v2 = y[7];
  const u3 = x[8];
  const v3 = y[8];
  const u4 = x[9];
  const v4 = y[9];

  let a0 = BigInt(x0) * BigInt(y0);
  let a1 = BigInt(x0) * BigInt(y1) + BigInt(x1) * BigInt(y0);
  let a2 = BigInt(x0) * BigInt(y2) + BigInt(x1) * BigInt(y1) + BigInt(x2) * BigInt(y0);
  let a3 = BigInt(x1) * BigInt(y2) + BigInt(x2) * BigInt(y1);

  a3 <<= BigInt(1);
  a3 += BigInt(x0) * BigInt(y3) + BigInt(x3) * BigInt(y0);

  let a4 = BigInt(x2) * BigInt(y2);

  a4 <<= BigInt(1);
  a4 += BigInt(x0) * BigInt(y4) + BigInt(x1) * BigInt(y3) + BigInt(x3) * BigInt(y1) + BigInt(x4) * BigInt(y0);

  let a5 = BigInt(x1) * BigInt(y4) + BigInt(x2) * BigInt(y3) + BigInt(x3) * BigInt(y2) + BigInt(x4) * BigInt(y1);

  a5 <<= BigInt(1);

  let a6 = BigInt(x2) * BigInt(y4) + BigInt(x4) * BigInt(y2);

  a6 <<= BigInt(1);
  a6 += BigInt(x3) * BigInt(y3);

  let a7 = BigInt(x3) * BigInt(y4) + BigInt(x4) * BigInt(y3);
  let a8 = BigInt(x4) * BigInt(y4);

  a8 <<= BigInt(1);

  const b0 = BigInt(u0) * BigInt(v0);
  const b1 = BigInt(u0) * BigInt(v1) + BigInt(u1) * BigInt(v0);
  const b2 = BigInt(u0) * BigInt(v2) + BigInt(u1) * BigInt(v1) + BigInt(u2) * BigInt(v0);
  let b3 = BigInt(u1) * BigInt(v2) + BigInt(u2) * BigInt(v1);

  b3 <<= BigInt(1);
  b3 += BigInt(u0) * BigInt(v3) + BigInt(u3) * BigInt(v0);

  let b4 = BigInt(u2) * BigInt(v2);

  b4 <<= BigInt(1);
  b4 += BigInt(u0) * BigInt(v4) + BigInt(u1) * BigInt(v3) + BigInt(u3) * BigInt(v1) + BigInt(u4) * BigInt(v0);

  const b5 = BigInt(u1) * BigInt(v4) + BigInt(u2) * BigInt(v3) + BigInt(u3) * BigInt(v2) + BigInt(u4) * BigInt(v1);
  let b6 = BigInt(u2) * BigInt(v4) + BigInt(u4) * BigInt(v2);

  b6 <<= BigInt(1);
  b6 += BigInt(u3) * BigInt(v3);

  const b7 = BigInt(u3) * BigInt(v4) + BigInt(u4) * BigInt(v3);
  const b8 = BigInt(u4) * BigInt(v4);

  a0 -= b5 * BigInt(76);
  a1 -= b6 * BigInt(38);
  a2 -= b7 * BigInt(38);
  a3 -= b8 * BigInt(76);
  a5 -= b0;
  a6 -= b1;
  a7 -= b2;
  a8 -= b3;

  x0 += u0;
  y0 += v0;
  x1 += u1;
  y1 += v1;
  x2 += u2;
  y2 += v2;
  x3 += u3;
  y3 += v3;
  x4 += u4;
  y4 += v4;

  const c0 = BigInt(x0) * BigInt(y0);
  const c1 = BigInt(x0) * BigInt(y1) + BigInt(x1) * BigInt(y0);
  const c2 = BigInt(x0) * BigInt(y2) + BigInt(x1) * BigInt(y1) + BigInt(x2) * BigInt(y0);
  let c3 = BigInt(x1) * BigInt(y2) + BigInt(x2) * BigInt(y1);

  c3 <<= BigInt(1);
  c3 += BigInt(x0) * BigInt(y3) + BigInt(x3) * BigInt(y0);

  let c4 = BigInt(x2) * BigInt(y2);

  c4 <<= BigInt(1);
  c4 += BigInt(x0) * BigInt(y4) + BigInt(x1) * BigInt(y3) + BigInt(x3) * BigInt(y1) + BigInt(x4) * BigInt(y0);

  let c5 = BigInt(x1) * BigInt(y4) + BigInt(x2) * BigInt(y3) + BigInt(x3) * BigInt(y2) + BigInt(x4) * BigInt(y1);

  c5 <<= BigInt(1);

  let c6 = BigInt(x2) * BigInt(y4) + BigInt(x4) * BigInt(y2);

  c6 <<= BigInt(1);
  c6 += BigInt(x3) * BigInt(y3);

  const c7 = BigInt(x3) * BigInt(y4) + BigInt(x4) * BigInt(y3);
  let c8 = BigInt(x4) * BigInt(y4);

  c8 <<= BigInt(1);

  let z8 = 0;
  let z9 = 0;
  let t = BigInt(0);

  t = a8 + (c3 - a3);
  z8 = Number(t & M26);
  t >>= BigInt(26);

  t += c4 - a4 - b4;
  z9 = Number(t & M25);
  t >>= BigInt(25);

  t = a0 + (t + c5 - a5) * BigInt(38);
  z[0] = Number(t & M26);
  t >>= BigInt(26);

  t += a1 + (c6 - a6) * BigInt(38);
  z[1] = Number(t & M26);
  t >>= BigInt(26);

  t += a2 + (c7 - a7) * BigInt(38);
  z[2] = Number(t& M25);
  t >>= BigInt(25);

  t += a3 + (c8 - a8) * BigInt(38);
  z[3] = Number(t & M26);
  t >>= BigInt(26);

  t += a4 + b4 * BigInt(38);
  z[4] = Number(t & M25);
  t >>= BigInt(25);

  t += a5 + (c0 - a0);
  z[5] = Number(t & M26);
  t >>= BigInt(26);

  t += a6 + (c1 - a1);
  z[6] = Number(t & M26);
  t >>= BigInt(26);

  t += a7 + (c2 - a2);
  z[7] = Number(t & M25);
  t >>= BigInt(25);

  t += BigInt(z8);
  z[8] = Number(t & M26);
  t >>= BigInt(26);

  z[9] = Number(z9 + Number(t));
}

export function negate(x: Int32Array, z: Int32Array): void {
  for (let i = 0; i < SIZE; i++) {
    z[i] = -x[i];
  }
}

export function normalize(z: Int32Array): void {
  const x = (z[9] >>> 23) & 1;
  reduce(z, x);
  reduce(z, -x);
}

export function one(z: Int32Array): void {
  z[0] = 1;

  for (let i = 1; i < SIZE; i++) {
    z[i] = 0;
  }
}

export function powPm5d8(x: Int32Array, rx2: Int32Array, rz: Int32Array) {
  const x2 = rx2;
  sqr(x, x2);
  mul2(x, x2, x2);

  const x3 = create();
  sqr(x2, x3);
  mul2(x, x3, x3);

  const x5 = x3;
  sqr2(x3, 2, x5);
  mul2(x2, x5, x5);

  const x10 = create();
  sqr2(x5, 5, x10);
  mul2(x5, x10, x10);

  const x15 = create();
  sqr2(x10, 5, x15);
  mul2(x5, x15, x15);

  const x25 = x5;
  sqr2(x15, 10, x25);
  mul2(x10, x25, x25);

  const x50 = x10;
  sqr2(x25, 25, x50);
  mul2(x25, x50, x50);

  const x75 = x15;
  sqr2(x50, 25, x75);
  mul2(x25, x75, x75);

  const x125 = x25;
  sqr2(x75, 50, x125);
  mul2(x50, x125, x125);

  const x250 = x50;
  sqr2(x125, 125, x250);
  mul2(x125, x250, x250);

  const t = x125;
  sqr2(x250, 2, t);
  mul2(t, x, rz);
}

export function reduce(z: Int32Array, c: number): void {
  let z9 = z[9];
  let t = z9;

  z9 = t & M24;
  t >>= 24;
  t = t + c;
  t = t * 19;
  t = t + z[0];
  z[0] = Number(t & M26);
  t >>= 26;
  t = t + z[1];
  z[1] = Number(t & M26);
  t >>= 26;
  t = t + z[2];
  z[2] = Number(t & M25);
  t >>= 25;
  t = t + z[3];
  z[3] = Number(t & M26);
  t >>= 26;
  t = t + z[4];
  z[4] = Number(t & M25);
  t >>= 25;
  t = t + z[5];
  z[5] = Number(t & M26);
  t >>= 26;
  t = t + z[6];
  z[6] = Number(t & M26);
  t >>= 26;
  t = t + z[7];
  z[7] = Number(t & M25);
  t >>= 25;
  t = t + z[8];
  z[8] = Number(t & M26);
  t >>= 26;
  t = t + z9;
  z[9] = Number(t);
}

export function sqr(x: Int32Array, z: Int32Array): void {
  // const M24 = BigInt(0x00ffffff);
  const M25 = BigInt(0x01ffffff);
  const M26 = BigInt(0x03ffffff);

  // Convert all values to BigInt to handle 64-bit operations
  let x0 = BigInt(x[0]);
  let x1 = BigInt(x[1]);
  let x2 = BigInt(x[2]);
  let x3 = BigInt(x[3]);
  let x4 = BigInt(x[4]);
  const u0 = BigInt(x[5]);
  const u1 = BigInt(x[6]);
  const u2 = BigInt(x[7]);
  const u3 = BigInt(x[8]);
  const u4 = BigInt(x[9]);

  // Double certain values
  let x1_2 = x1 * BigInt(2);
  let x2_2 = x2 * BigInt(2);
  let x3_2 = x3 * BigInt(2);
  let x4_2 = x4 * BigInt(2);

  // Compute 'a' values
  let a0 = x0 * x0;
  let a1 = x0 * x1_2;
  let a2 = x0 * x2_2 + x1 * x1;
  let a3 = x1_2 * x2_2 + x0 * x3_2;
  let a4 = x2 * x2_2 + x0 * x4_2 + x1 * x3_2;
  let a5 = x1_2 * x4_2 + x2_2 * x3_2;
  let a6 = x2_2 * x4_2 + x3 * x3;
  let a7 = x3 * x4_2;
  let a8 = x4 * x4_2;

  // Double 'u' values
  const u1_2 = u1 * BigInt(2);
  const u2_2 = u2 * BigInt(2);
  const u3_2 = u3 * BigInt(2);
  const u4_2 = u4 * BigInt(2);

  // Compute 'b' values
  const b0 = u0 * u0;
  const b1 = u0 * u1_2;
  const b2 = u0 * u2_2 + u1 * u1;
  const b3 = u1_2 * u2_2 + u0 * u3_2;
  const b4 = u2 * u2_2 + u0 * u4_2 + u1 * u3_2;
  const b5 = u1_2 * u4_2 + u2_2 * u3_2;
  const b6 = u2_2 * u4_2 + u3 * u3;
  const b7 = u3 * u4_2;
  const b8 = u4 * u4_2;

  // Adjust 'a' values
  a0 -= b5 * BigInt(38);
  a1 -= b6 * BigInt(38);
  a2 -= b7 * BigInt(38);
  a3 -= b8 * BigInt(38);
  a5 -= b0;
  a6 -= b1;
  a7 -= b2;
  a8 -= b3;

  // Update 'x' values
  x0 += u0;
  x1 += u1;
  x2 += u2;
  x3 += u3;
  x4 += u4;
  x1_2 = x1 * BigInt(2);
  x2_2 = x2 * BigInt(2);
  x3_2 = x3 * BigInt(2);
  x4_2 = x4 * BigInt(2);

  // Compute 'c' values
  const c0 = x0 * x0;
  const c1 = x0 * x1_2;
  const c2 = x0 * x2_2 + x1 * x1;
  const c3 = x1_2 * x2_2 + x0 * x3_2;
  const c4 = x2 * x2_2 + x0 * x4_2 + x1 * x3_2;
  const c5 = x1_2 * x4_2 + x2_2 * x3_2;
  const c6 = x2_2 * x4_2 + x3 * x3;
  const c7 = x3 * x4_2;
  const c8 = x4 * x4_2;

  let z8 = BigInt(0);
  let z9 = BigInt(0);
  let t = BigInt(0);

  t = a8 + (c3 - a3);
  z8 = t & M26;
  t >>= BigInt(26);
  t += (c4 - a4) - b4;
  z9 = t & M25;
  t >>= BigInt(25);
  t = a0 + (t + c5 - a5) * BigInt(38);
  z[0] = Number(t & M26);
  t >>= BigInt(26);
  t += a1 + (c6 - a6) * BigInt(38);
  z[1] = Number(t & M26);
  t >>= BigInt(26);
  t += a2 + (c7 - a7) * BigInt(38);
  z[2] = Number(t & M25);
  t >>= BigInt(25);
  t += a3 + (c8 - a8) * BigInt(38);
  z[3] = Number(t & M26);
  t >>= BigInt(26);
  t += a4 + b4 * BigInt(38);
  z[4] = Number(t & M25);
  t >>= BigInt(25);
  t += a5 + (c0 - a0);
  z[5] = Number(t & M26);
  t >>= BigInt(26);
  t += a6 + (c1 - a1);
  z[6] = Number(t & M26);
  t >>= BigInt(26);
  t += a7 + (c2 - a2);
  z[7] = Number(t & M25);
  t >>= BigInt(25);
  t += z8;
  z[8] = Number(t & M26);
  t >>= BigInt(26);
  z[9] = Number(z9 + t);
}

export function sqr2(x: Int32Array, n: number, z: Int32Array): void {
  let nv = n;

  sqr(x, z);

  while (--nv > 0) {
    sqr(z, z);
  }
}

export function sqrtRatioVar(u: Int32Array, v: Int32Array, z: Int32Array): boolean {
  const uv3 = create();
  const uv7 = create();

  mul2(u, v, uv3);
  sqr(v, uv7);
  mul2(uv3, uv7, uv3);
  sqr(uv7, uv7);
  mul2(uv7, uv3, uv7);

  const t = create();
  const x = create();

  powPm5d8(uv7, t, x);
  mul2(x, uv3, x);

  const vx2 = create();
  sqr(x, vx2);
  mul2(vx2, v, vx2);

  sub(vx2, u, t);
  normalize(t);

  if (isZeroVar(t)) {
    copy(x, 0, z, 0);
    return true;
  }

  add(vx2, u, t);
  normalize(t);

  if (isZeroVar(t)) {
    mul2(x, ROOT_NEG_ONE, z);
    return true;
  }

  return false;
}

export function sub(x: Int32Array, y: Int32Array, z: Int32Array) {
  for (let i = 0; i < SIZE; i++) {
    z[i] = x[i] - y[i];
  }
}

export function subOne(z: Int32Array) {
  z[0] -= 1;
}

export function zero(z: Int32Array) {
  for (let i = 0; i < SIZE; i++) {
    z[i] = 0;
  }
}
