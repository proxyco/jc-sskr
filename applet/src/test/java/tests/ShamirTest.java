/*
 * Original adapted: https://github.com/BlockchainCommons/bc-shamir
 */

/*
 * Copyright © 2023 Proxy, Inc (proxy.com)
 * Licensed under the "BSD-2-Clause Plus Patent License"
 */

package tests;

import com.proxy.sskr.Shamir;

import com.licel.jcardsim.utils.ByteUtil;

import javacard.framework.*;
import javacard.security.*;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.jupiter.api.*;

public class ShamirTest
{
  class MockRandomData extends RandomData
  {
    public void generateData(byte[] buffer, short offset, short length)
    {
      byte b = 0;
      for (short i = 0; i < length; i++) {
        buffer[(short)(offset + i)] = b;
        b += 17;
      }
    }

    public byte getAlgorithm()
    {
      return RandomData.ALG_PSEUDO_RANDOM;
    }

    public void setSeed(byte[] buffer, short offset, short length) { }
    public short nextBytes(byte[] buffer, short offset, short length) { return (short) 0; }
  }

  Shamir shamir;

  public ShamirTest() {
  }

  @BeforeAll
  public static void setUpClass() throws Exception {
  }

  @AfterAll
  public static void tearDownClass() throws Exception {
  }

  @BeforeEach
  public void setUpMethod() throws Exception {
    shamir = new Shamir(new MockRandomData(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
  }

  @AfterEach
  public void tearDownMethod() throws Exception {
  }

  void roundtrip(byte[] secret, byte t, byte n, byte[] x)
  {
    byte[] shares = new byte[secret.length * n];
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares = new byte[secret.length * t];

    short i;

    System.out.println("secret: " + ByteUtil.hexString(secret));

    shamir.split(t, n, secret, (short) 0, (short)(secret.length), shares, (short) 0);

    for (i = 0; i < n; i++) {
      System.out.println(i + ": " +
          ByteUtil.hexString(shares, (short)(i * secret.length), (short) secret.length));
    }

    for (i = 0; i < x.length; i++) {
      javacard.framework.Util.arrayCopyNonAtomic(
          shares, (short)(secret.length * x[i]),
          recoveredShares, (short)(secret.length * i), (short) secret.length);
      System.out.println("from " + x[i] + ": " +
          ByteUtil.hexString(recoveredShares, (short)(secret.length * i), (short) secret.length));
    }

    short result = shamir.combine((byte) x.length, x,
        recoveredShares, (short) 0, (short) recoveredShares.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertArrayEquals(secret, recoveredSecret);
  }

  @Test
  void roundtrip1() throws Exception
  {
    roundtrip(
      ByteUtil.byteArray("0ff784df000c4380a5ed683f7e6e3dcf"),
      (byte) 1, (byte) 2, new byte[] {0});
  }

  @Test
  void roundtrip2() throws Exception
  {
    roundtrip(
      ByteUtil.byteArray("0ff784df000c4380a5ed683f7e6e3dcf"),
      (byte) 3, (byte) 5, new byte[] {1, 2, 4});
  }

  @Test
  void roundtrip3() throws Exception
  {
    roundtrip(
      ByteUtil.byteArray("204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a"),
      (byte) 2, (byte) 7, new byte[] {3, 4});
  }

  @Test
  void recoverFromReference1() throws Exception
  {
    // from reference implementation at https://github.com/BlockchainCommons/bc-shamir
    byte[] secret = ByteUtil.byteArray(
      "0ff784df000c4380a5ed683f7e6e3dcf");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares = ByteUtil.byteArray(
      "d43099fe444807c46921a4f33a2a798b" +
      "d9ad4e3bec2e1a7485698823abf05d36" +
      "1aa7fe3199bc5092ef3816b074cabdf2");

    short result = shamir.combine((byte) 3, new byte[] {1, 2, 4},
        recoveredShares, (short) 0, (short) recoveredShares.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertArrayEquals(secret, recoveredSecret);
  }

  @Test
  void recoverFromReference2() throws Exception
  {
    // from reference implementation at https://github.com/BlockchainCommons/bc-shamir
    byte[] secret = ByteUtil.byteArray(
      "204188bfa6b440a1bdfd6753ff55a8241e07af5c5be943db917e3efabc184b1a");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares = ByteUtil.byteArray(
      "a2fb5414d4d96ee58a109b3ca9a84be0259d2c0f9ac92bdd3199e0eed3f1dd3e" +
      "2b851d188b8f5b3653659cc0f7fa45102dadf04b708767385cd803862fcb3c3f");

    short result = shamir.combine((byte) 2, new byte[] {3, 4},
        recoveredShares, (short) 0, (short) recoveredShares.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertArrayEquals(secret, recoveredSecret);
  }
}
