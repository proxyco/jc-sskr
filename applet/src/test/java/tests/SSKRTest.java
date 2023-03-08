/*
 * Original adapted: https://github.com/BlockchainCommons/bc-sskr
 */

/*
 * Copyright © 2023 Proxy, Inc (proxy.com)
 * Licensed under the "BSD-2-Clause Plus Patent License"
 */

package tests;

import com.proxy.sskr.SSKR;

import com.licel.jcardsim.utils.ByteUtil;

import javacard.framework.*;
import javacard.security.*;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.jupiter.api.*;

public class SSKRTest
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

  SSKR sskr;

  public SSKRTest() {
  }

  @BeforeAll
  public static void setUpClass() throws Exception {
  }

  @AfterAll
  public static void tearDownClass() throws Exception {
  }

  @BeforeEach
  public void setUpMethod() throws Exception {
    sskr = new SSKR(new MockRandomData(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
  }

  @AfterEach
  public void tearDownMethod() throws Exception {
  }

  void roundtrip(byte[] secret, byte groupThreshold, byte[] groups, byte[] x)
  {
    short i;
    short shareCount = 0;
    short shareLen = (short)(secret.length + SSKR.METADATA_SIZE);

    for (i = 1; i < groups.length; i += 2) {
      shareCount += groups[i];
    }

    byte[] shares = new byte[shareCount * shareLen];
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares = new byte[x.length * shareLen];

    System.out.println("secret: " + ByteUtil.hexString(secret));

    sskr.generateShares(groupThreshold, groups,
        secret, (short) 0, (short)(secret.length), shares, (short) 0);

    for (i = 0; i < shareCount; i++) {
      System.out.println(i + ": " + ByteUtil.hexString(shares, (short)(i * shareLen), shareLen));
    }

    for (i = 0; i < x.length; i++) {
      javacard.framework.Util.arrayCopyNonAtomic(
          shares, (short)(shareLen * x[i]), recoveredShares, (short)(shareLen * i), shareLen);
      System.out.println("from " + x[i] + " (" +
          (recoveredShares[shareLen * i + 3] >> 4 & 0xf) + "." +
          (recoveredShares[shareLen * i + 4] & 0xf) + "): " +
          ByteUtil.hexString(recoveredShares, (short)(shareLen * i), shareLen));
    }

    short result = sskr.combineShares((byte) x.length,
        recoveredShares, (short) 0, (short) recoveredShares.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertArrayEquals(secret, recoveredSecret);
  }

  @Test
  void roundtrip1() throws Exception
  {
    // single group, 2-of-3
    roundtrip(ByteUtil.byteArray("7daa851251002874e1a1995f0897e6b1"),
        (byte) 1, new byte[] {2, 3}, new byte[] {0, 1, 2});
  }

  @Test
  void roundtrip2() throws Exception
  {
    // two groups, 2-of-3 and 3-of-5
    roundtrip(ByteUtil.byteArray("7daa851251002874e1a1995f0897e6b1"),
        (byte) 2, new byte[] {2, 3, 3, 5}, new byte[] {1, 2, 3, 5, 6});
  }

  @Test
  void recoverFromReference1() throws Exception
  {
    // from reference implementation at https://github.com/BlockchainCommons/bc-sskr
    byte[] secret = ByteUtil.byteArray(
      "7daa851251002874e1a1995f0897e6b1");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares = ByteUtil.byteArray(
      "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f" +
      "4bbf1101025abd490ee65b6084859854ee67736e75" +
      "4bbf11120044ef453f66923d32653b377de5c94b39" +
      "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd" +
      "4bbf11120388626f665fc4c0e545e0c2ff0c26368f");

    short result = sskr.combineShares((byte) 5,
        recoveredShares, (short) 0, (short) recoveredShares.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertArrayEquals(secret, recoveredSecret);
  }

  @Test
  void recoverWithTwoTransactions() throws Exception
  {
    byte[] secret = ByteUtil.byteArray(
      "7daa851251002874e1a1995f0897e6b1");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares1 = ByteUtil.byteArray(
      "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f" + // #0.1
      "4bbf1101025abd490ee65b6084859854ee67736e75"); // #0.2
    byte[] recoveredShares2 = ByteUtil.byteArray(
      "4bbf11120044ef453f66923d32653b377de5c94b39" + // #1.0
      "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd" + // #1.2
      "4bbf11120388626f665fc4c0e545e0c2ff0c26368f"); // #1.3

    short result;

    result = sskr.combineShares((byte) 2,
        recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);

    Assert.assertEquals(0, result);

    result = sskr.combineShares((byte) 3,
        recoveredShares2, (short) 0, (short) recoveredShares2.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertEquals(secret.length, result);
    Assert.assertArrayEquals(secret, recoveredSecret);
  }

  @Test
  void recoverWithDuplicates() throws Exception
  {
    byte[] secret = ByteUtil.byteArray(
      "7daa851251002874e1a1995f0897e6b1");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares1 = ByteUtil.byteArray(
      "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f" + // #0.1
      "4bbf1101025abd490ee65b6084859854ee67736e75"); // #0.2
    byte[] recoveredShares2 = ByteUtil.byteArray(
      "4bbf11120044ef453f66923d32653b377de5c94b39" + // #1.0
      "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd" + // #1.2
      "4bbf11120388626f665fc4c0e545e0c2ff0c26368f"); // #1.3

    short result;

    result = sskr.combineShares((byte) 2,
        recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);

    Assert.assertEquals(0, result);

    // re-send duplicate shares for group that was already recovered
    result = sskr.combineShares((byte) 2,
        recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);

    Assert.assertEquals(0, result);

    result = sskr.combineShares((byte) 3,
        recoveredShares2, (short) 0, (short) recoveredShares2.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertEquals(secret.length, result);
    Assert.assertArrayEquals(secret, recoveredSecret);
  }

  @Test
  void recoverWithPartialTransactions() throws Exception
  {
    byte[] secret = ByteUtil.byteArray(
      "7daa851251002874e1a1995f0897e6b1");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares1 = ByteUtil.byteArray(
      "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f" + // #0.1
      "4bbf11120388626f665fc4c0e545e0c2ff0c26368f"); // #1.3
    byte[] recoveredShares2 = ByteUtil.byteArray(
      "4bbf11120044ef453f66923d32653b377de5c94b39" + // #1.0
      "4bbf1101025abd490ee65b6084859854ee67736e75" + // #0.2
      "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd" + // #1.2
      "4bbf11120388626f665fc4c0e545e0c2ff0c26368f"); // #1.3

    short result;

    result = sskr.combineShares((byte) 2,
        recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);

    Assert.assertEquals(0, result);

    result = sskr.combineShares((byte) 4,
        recoveredShares2, (short) 0, (short) recoveredShares2.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertEquals(secret.length, result);
    Assert.assertArrayEquals(secret, recoveredSecret);
  }

  @Test
  void invalidShareId() throws Exception
  {
    byte[] secret = ByteUtil.byteArray(
      "7daa851251002874e1a1995f0897e6b1");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares1 = ByteUtil.byteArray(
      "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f" + // #0.1
      "4ccf1101025abd490ee65b6084859854ee67736e75"); // #0.2

    short result;

    CryptoException e = Assert.assertThrows(CryptoException.class, () -> {
      sskr.combineShares((byte) 2,
          recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);
    });
    Assert.assertEquals(CryptoException.ILLEGAL_USE, e.getReason());
  }

  @Test
  void invalidShareValue() throws Exception
  {
    byte[] secret = ByteUtil.byteArray(
      "7daa851251002874e1a1995f0897e6b1");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares1 = ByteUtil.byteArray(
      "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f" + // #0.1
      "4bbf1101025abd490ee65b6084859854ee67736e76"); // #0.2

    short result;

    CryptoException e = Assert.assertThrows(CryptoException.class, () -> {
      sskr.combineShares((byte) 2,
          recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);
    });
    Assert.assertEquals(CryptoException.ILLEGAL_VALUE, e.getReason());
  }

  @Test
  void reset() throws Exception
  {
    byte[] secret = ByteUtil.byteArray(
      "7daa851251002874e1a1995f0897e6b1");
    byte[] recoveredSecret = new byte[secret.length];
    byte[] recoveredShares1 = ByteUtil.byteArray(
      "4bbf1101010c8ba39a7502a325ed07b8d597d1b80f" + // #0.1
      "4bbf1101025abd490ee65b6084859854ee67736e75"); // #0.2
    byte[] recoveredShares2 = ByteUtil.byteArray(
      "4bbf11120044ef453f66923d32653b377de5c94b39" + // #1.0
      "4bbf111202a3763155fcfdb5887abce6ee69c4bbcd" + // #1.2
      "4bbf11120388626f665fc4c0e545e0c2ff0c26368f"); // #1.3

    short result;

    result = sskr.combineShares((byte) 2,
        recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);

    Assert.assertEquals(0, result);

    // clear internal state
    sskr.reset();

    result = sskr.combineShares((byte) 3,
        recoveredShares2, (short) 0, (short) recoveredShares2.length, recoveredSecret, (short) 0);

    Assert.assertEquals(0, result);

    result = sskr.combineShares((byte) 2,
        recoveredShares1, (short) 0, (short) recoveredShares1.length, recoveredSecret, (short) 0);

    System.out.println("recovered secret: " + ByteUtil.hexString(recoveredSecret));
    System.out.println("verified secret: " + (result == secret.length));

    Assert.assertEquals(secret.length, result);
    Assert.assertArrayEquals(secret, recoveredSecret);
  }
}
