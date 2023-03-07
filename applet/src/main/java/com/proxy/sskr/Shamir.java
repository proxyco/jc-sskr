/*
 * Original adapted: https://github.com/BlockchainCommons/bc-shamir
 */

/*
 * Copyright © 2023 Proxy, Inc (proxy.com)
 * Licensed under the "BSD-2-Clause Plus Patent License"
 */

package com.proxy.sskr;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;

/**
 * An implementation of Shamir's Secret Sharing over GF(256) to securely split secrets
 * into `N` shares, of which any `T` can be combined to recover the original secret.
 *
 * Uses the strategy described in SLIP-39 for compatibility with existing implementations.
 *
 * @see <a href="https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing">Shamir's Secret Sharing</a>
 * @see <a href="https://github.com/satoshilabs/slips/blob/master/slip-0039.md">SLIP-39</a>
 */
public class Shamir
{
  public final static byte MAX_SHARE_COUNT = (byte) 16;
  public final static byte MAX_SECRET_SIZE = (byte) 32;
  public final static byte MIN_SECRET_SIZE = (byte) 16;
  public final static byte DIGEST_SIZE = (byte) 4;

  private RandomData random;
  private Signature signer;

  // temporary memory for calculating and verifying secret digest
  private byte[] digest;
  private byte[] sig;

  /**
   * Instantiates a new instance.
   */
  public Shamir(RandomData randomSource) {
    random = randomSource;
    // reserve extra DIGEST_SIZE bytes at the end for use in verification
    digest = JCSystem.makeTransientByteArray(
        (short)(MAX_SECRET_SIZE + DIGEST_SIZE), JCSystem.CLEAR_ON_DESELECT);
    sig = JCSystem.makeTransientByteArray(
        (short)(MessageDigest.LENGTH_SHA_256), JCSystem.CLEAR_ON_DESELECT);
    signer = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
  }

  /**
   * Calculates the digest of the data using HMAC-SHA-256 with a random key, and writes
   * the first `DIGEST_SIZE` bytes of the digest to the output buffer.
   */
  private void createDigest(
      byte[] randomData, short randomDataOff, short randomDataLen,
      byte[] data, short dataOff, short dataLen,
      byte[] out, short outOff)
  {
    HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
        (short)(randomDataLen << 3) /* key length in bits */, false);
    key.setKey(randomData, randomDataOff, randomDataLen);

    signer.init(key, Signature.MODE_SIGN);
    signer.sign(data, dataOff, dataLen, sig, (short) 0);
    out[outOff++] = sig[0];
    out[outOff++] = sig[1];
    out[outOff++] = sig[2];
    out[outOff++] = sig[3];
  }

  /**
   * Splits the given secret into `N` shares, of which any `T` or more can be combined
   * to recover the original secret.
   *
   * Shares are numbered 0..(n-1), matching their index to their x-coordinate, which
   * differs from Shamir implementations that place the original secret at x = 0.
   * The secret can be found at x = 255, and a digest of the secret at x = 254.
   *
   * @see <a href="https://github.com/satoshilabs/slips/blob/master/slip-0039.md">SLIP-39</a>
   *
   * @param t           threshold number of shares required to recover the secret
   * @param n           total number of shares
   * @param secret      buffer containing the secret to split
   * @param secretOff   offset into the secret buffer
   * @param secretLen   length of the secret
   * @param shares      output buffer for generated shares; length `n * secretLen`
   * @param sharesOff   offset into the output buffer to start writing
   *
   * @return number of bytes written to the output buffer.
   *
   * @throws `CryptoException.ILLEGAL_VALUE` if `t` or `n` do not satisfy `1 ≤ t ≤ n ≤ 16`, or
   *    if the secret length is less than 16 bytes or greater than 32 bytes.
   */
  public short split(byte t, byte n,
      byte[] secret, short secretOff, short secretLen,
      byte[] shares, short sharesOff)
  {
    short i, j, k;

    if (secretLen < MIN_SECRET_SIZE || secretLen > MAX_SECRET_SIZE || (secretLen & 1) != 0) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (t <= 0 || t > n || n > MAX_SHARE_COUNT) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (t == 1) {
      // just return `n` copies of the secret
      for (i = 0; i < n; i++, sharesOff += secretLen) {
        Util.arrayCopyNonAtomic(secret, secretOff, shares, sharesOff, secretLen);
      }
      return (short)(n * secretLen);
    }

    // generate a digest of the secret as a checksum
    random.generateData(digest, (short) DIGEST_SIZE, (short)(secretLen - DIGEST_SIZE));

    createDigest(digest, (short) DIGEST_SIZE, (short)(secretLen - DIGEST_SIZE),
        secret, secretOff, secretLen,
        digest, (short) 0);

    // generate y_1 .. y_(t-2) shares randomly
    if (t > 2) {
      random.generateData(shares, sharesOff, (short)((t - 2) * secretLen));
    }

    // points are stored as a sequence of coordinates [x_1, y_1, .., x_t, y_t]
    // allocate dynamically because we do not want to reserve transient memory
    // for the maximum case; may fail with SystemException.NO_TRANSIENT_SPACE.
    byte[] points = JCSystem.makeTransientByteArray((short)(t * 2), JCSystem.CLEAR_ON_DESELECT);
    for (i = 0; i < secretLen; i++) {
      // compute shares y_i for (t - 2) < i ≤ n using Lagrange interpolation at x_i = (i - 1)
      // across the set of points:
      //  {
      //    (0, y_1), .., (t - 3, y_(t-2)), (254, digest), (255, secret)
      //  }
      for (j = 0, k = 0; j < (short)(t - 2); j++) {
        points[k++] = (byte) j;
        points[k++] = shares[(short)(sharesOff + j * secretLen + i)];
      }
      points[k++] = (byte) 0xfe;
      points[k++] = digest[i];
      points[k++] = (byte) 0xff;
      points[k++] = secret[(short)(secretOff + i)];

      for (j = (short)(t - 2); j < n; j++) {
        shares[(short)(sharesOff + j * secretLen + i)] = GF256.interpolate((byte) j, points);
      }
    }
    return (short)(n * secretLen);
  }

  /**
   * Combines shares to recover a secret.
   *
   * @param t         number of available shares
   * @param x         array of x coordinates (indices of available shares); length `t`
   * @param shares    buffer containing `t` shares, concatenated back to back
   * @param sharesOff offset into the shares buffer
   * @param sharesLen length of the shares buffer; must be a multiple of `t`
   * @param secret    output buffer for the recovered secret; length `sharesLen / t`
   * @param secretOff offset into the secret buffer to start writing
   *
   * @return number of bytes written to the output buffer, or 0 if checksum verification failed.
   *
   * Note: There is no guaranteed way to determine whether or not the combined value
   * is actually the original secret. If the shares are incorrect or are under the
   * threshold number required for recovery, a non-zero value may be returned even
   * though the secret is not recovered correctly, with probability 2^-32.
   *
   * @throws `CryptoException.ILLEGAL_VALUE` if `sharesLen` is not a multiple of `t`,
   *    if the secret length is less than 16 bytes or greater than 32 bytes, or
   *    if `t` does not satisfy `1 ≤ t ≤ 16`.
   */
  public short combine(byte t, byte[] x,
      byte[] shares, short sharesOff, short sharesLen,
      byte[] secret, short secretOff)
  {
    short i, j, k, secretLen;

    if (sharesLen == 0 || (sharesLen % t) != 0) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    secretLen = (short)(sharesLen / t);
    if (secretLen < MIN_SECRET_SIZE || secretLen > MAX_SECRET_SIZE || (secretLen & 1) != 0) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    if (t <= 0 || t > MAX_SHARE_COUNT) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (t == 1) {
      // just return the first share
      Util.arrayCopyNonAtomic(shares, sharesOff, secret, secretOff, secretLen);
      return secretLen;
    }

    // points are stored as a sequence of coordinates [x_1, y_1, .., x_t, y_t]
    // allocate dynamically because we do not want to reserve transient memory
    // for the maximum case; may fail with SystemException.NO_TRANSIENT_SPACE.
    byte[] points = JCSystem.makeTransientByteArray((short)(t * 2), JCSystem.CLEAR_ON_DESELECT);
    for (i = 0; i < secretLen; i++) {
      for (j = 0, k = 0; j < t; j++) {
        points[k++] = x[j];
        points[k++] = shares[(short)(sharesOff + j * secretLen + i)];
      }
      secret[(short)(secretOff + i)] = GF256.interpolate((byte) 0xff, points);
      digest[i] = GF256.interpolate((byte) 0xfe, points);
    }

    // verify digest (verification digest is generated at the tail end of the buffer)
    createDigest(digest, (short) DIGEST_SIZE, (short)(secretLen - DIGEST_SIZE),
        secret, secretOff, secretLen, digest, secretLen);

    if (Util.arrayCompare(digest, (short) 0, digest, secretLen, (short) DIGEST_SIZE) == 0) {
      return secretLen;
    }
    return 0;
  }
}
