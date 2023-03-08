/*
 * Copyright © 2023 Proxy, Inc (proxy.com)
 * Licensed under the "BSD-2-Clause Plus Patent License"
 */

package com.proxy.sskr;

import javacard.framework.*;
import javacard.security.*;

/**
 * Cryptographic primitives.
 */
public class Crypto
{
  private static Crypto instance;

  final static private byte HMAC_IPAD = (byte) 0x36;
  final static private byte HMAC_OPAD = (byte) 0x5C;
  private byte[] block;

  MessageDigest sha256;
  MessageDigest sha512;

  private byte[] signature;

  Crypto()
  {
    // big enough for SHA-256 and SHA-512 blocks
    block = JCSystem.makeTransientByteArray(
        KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128, JCSystem.CLEAR_ON_RESET);

    sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);

    // big enough for a HMAC-SHA-512 signature (64).
    signature = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);
  }

  static Crypto getInstance()
  {
    if (Crypto.instance == null) {
      Crypto.instance = new Crypto();
    }
    return Crypto.instance;
  }

  static void releaseInstance()
  {
    Crypto.instance = null;
  }

  void hmac(
      MessageDigest md, short mdLen, short blockLen,
      byte[] key, short keyOff, short keyLen,
      byte[] in, short inOff, short inLen,
      byte[] out, short outOff)
  {
    for (short i = 0; i < 2; i++) {
      Util.arrayFillNonAtomic(block, (short) 0, blockLen, (i == 0 ? HMAC_IPAD : HMAC_OPAD));
      for (short j = 0; j < keyLen; j++) {
        block[j] ^= key[(short)(keyOff + j)];
      }

      md.update(block, (short) 0, blockLen);

      if (i == 0) {
        md.doFinal(in, inOff, inLen, out, outOff);
      } else {
        md.doFinal(out, outOff, mdLen, out, outOff);
      }
    }
  }

  void hmac256(
      byte[] key, short keyOff, short keyLen,
      byte[] in, short inOff, short inLen,
      byte[] out, short outOff)
  {
    hmac(sha256, MessageDigest.LENGTH_SHA_256,
        KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64,
        key, keyOff, keyLen,
        in, inOff, inLen,
        out, outOff);
  }

  void hmac256(
      byte[] key, short keyOff, short keyLen,
      byte[] in, short inOff, short inLen,
      byte[] out, short outOff, short outLen)
  {
    hmac(sha256, MessageDigest.LENGTH_SHA_256,
        KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64,
        key, keyOff, keyLen,
        in, inOff, inLen,
        signature, (short) 0);
    Util.arrayCopy(signature, (short) 0, out, outOff, outLen);
  }

  void hmac512(
      byte[] key, short keyOff, short keyLen,
      byte[] in, short inOff, short inLen,
      byte[] out, short outOff)
  {
    hmac(sha512, MessageDigest.LENGTH_SHA_512,
        KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128,
        key, keyOff, keyLen,
        in, inOff, inLen,
        out, outOff);
  }

  void hmac512(
      byte[] key, short keyOff, short keyLen,
      byte[] in, short inOff, short inLen,
      byte[] out, short outOff, short outLen)
  {
    hmac(sha512, MessageDigest.LENGTH_SHA_512,
        KeyBuilder.LENGTH_HMAC_SHA_512_BLOCK_128,
        key, keyOff, keyLen,
        in, inOff, inLen,
        signature, (short) 0);
    Util.arrayCopy(signature, (short) 0, out, outOff, outLen);
  }
}
