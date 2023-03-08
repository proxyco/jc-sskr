/*
 * Original adapted: https://github.com/BlockchainCommons/bc-sskr
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
 * An implementation of Sharded Secret Key Reconstruction (SSKR).
 *
 * This class provides a stateful recovery mechanism, allowing shares to be accumulated
 * until the threshold for recovery of a secret is met. This is necessary to operate on
 * a JavaCard where shares may be supplied in multiple write transactions, and power is
 * removed between transactions.
 *
 * Accumulated state can be `reset` to allow a new set shares to be combined. This must
 * be done after a successful recovery of a secret, or whenever an error is encountered
 * during recovery after a subset of shares has been written.
 *
 * @see <a href="https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md">SSKR</a>
 */
public class SSKR
{
  public final static byte MAX_SHARE_COUNT = Shamir.MAX_SHARE_COUNT;
  public final static byte METADATA_SIZE = (byte) 5;

  private RandomData randomSource;
  private Shamir shamir;

  // identifier of the share set currently being reconstructed
  private short pendingId;

  // length of `pendingGroupY` and `pendingGroupX` is equal to the total group count `g`,
  // where each index `i` corresponds to that group's x-coordinate.
  // each element is a byte[] large enough to hold `t_i` shares of the group `i : 1 ≤ i ≤ g`.
  private Object[] pendingGroupY;
  // each element is a byte[] containing x-coordinates for each share `j : 1 ≤ j ≤ t_i`,
  // or the value `0xff` for shares that have not been filled yet (note that `0xff` is
  // not a valid x-coordinate for a share).
  private Object[] pendingGroupX;

  // length of `pendingY` is large enough to hold `groupThreshold` shares.
  // once any group share above is successfully recovered, it is added to this buffer,
  // and the corresponding x-coordinate is added to `pendingX`; master secret recovery
  // is attempted once all `groupThreshold` shares are filled.
  private byte[] pendingY;
  // length of `pendingX` is equal to `groupThreshold`.
  // each element is the x-coordinates for the corresponding group share `i : 1 ≤ i ≤ g`,
  // or the value `0xff` for shares that have not been filled yet (note that `0xff` is
  // not a valid x-coordinate for a share).
  private byte[] pendingX;

  // sentinel value for shares that have not yet been filled.
  private final static byte UNUSED = (byte) 0xff;

  // set default allocation type to CLEAR_ON_RESET transient memory.
  private byte memoryType = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;

  public SSKR(RandomData randomSource, byte memoryType)
  {
    this.randomSource = randomSource;
    this.memoryType = memoryType;
    shamir = new Shamir(randomSource, memoryType);
  }

  /**
   * Allocates a buffer of appropriate memory type.
   */
  private byte[] createBuffer(short size)
  {
    switch (memoryType) {
      case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
        return JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
      case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
        return JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_RESET);
      case JCSystem.MEMORY_TYPE_PERSISTENT:
      default:
        return new byte[size];
    }
  }

  /**
   * Generates a set of serialized shares that can be combined to reconstruct the secret
   * using the given group policy.
   *
   * @param groupThreshold  number of groups that need to be satisfied to recover the secret
   * @param groups          group descriptors, given as a sequence `[t_1, n_1, .., t_g, n_g]`
   *                        where `t_i` is the member threshold, `n_i` is the member count of
   *                        each group `1 ≤ i ≤ g`, and group count `g` is `groups.length / 2`;
   *                        must have a length that is a multiple of `2`
   * @param secret          buffer containing the secret to split
   * @param secretOff       offset into the secret buffer
   * @param secretLen       length of the secret; must be ≥16 and ≤32
   * @param shares          output buffer for generated shares; large enough to fit all encoded
   *                        shares `∑ n_i ∀i : 1 ≤ i ≤ g`, length `(METADATA_SIZE + secretLen)`
   *                        bytes each
   * @param sharesOff       offset into the output buffer to start writing
   *
   * @throws `CryptoException.ILLEGAL_VALUE` if `groups` length is not a multiple of `2`;
   *    if `groupThreshold` or `groups` do not satisfy `1 ≤ groupsThreshold ≤ g ≤ 16`; or
   *    if `groups` does not satisfy `1 ≤ t_i ≤ n_i ≤ 16` for any `1 ≤ i ≤ g`.
   */
  public short generateShares(byte groupThreshold, byte[] groups,
      byte[] secret, short secretOff, short secretLen,
      byte[] shares, short sharesOff)
  {
    byte groupCount, t, n;
    short groupStart;
    short id;
    short i, j;

    if (groups.length % 2 != 0) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    groupCount = (byte)(groups.length / 2);

    if (groupThreshold <= 0 || groupThreshold > groupCount) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    // how much space do we need for intermediate storage?
    // - for group shares: group count (g) * secretLen
    //   - for each group: n_i * secretLen; can be reused after encoding into the output buffer
    //
    // nominally, this is at most (16 * 32) + (16 * 32) = 1024 bytes, which is a lot to reserve.
    // instead, we try to allocate dynamically only what is needed.
    // this may throw `SystemException.NO_TRANSIENT_SPACE`.
    byte[] buf = createBuffer((short)((groupCount + largestGroup(groups)) * secretLen));

    // generate a random identifier
    randomSource.generateData(buf, (short) 0, (short) 2);
    id = Util.getShort(buf, (short) 0);

    // generate group shares
    groupStart = shamir.split(
        groupThreshold, groupCount, secret, secretOff, secretLen, buf, (short) 0);

    // for each group, split the group share into individual shares
    for (i = 0; i < groupCount; i++) {
      t = groups[(short)(i * 2)];
      n = groups[(short)(i * 2 + 1)];
      shamir.split(t, n, buf, (short)(i * secretLen), secretLen, buf, groupStart);

      for (j = 0; j < n; j++) {
        sharesOff = serializeShare(id, groupCount, groupThreshold, (byte) i, t, (byte) j,
            buf, (short)(groupStart + j * secretLen), secretLen, shares, sharesOff);
      }
    }
    return sharesOff;
  }

  /**
   * Combines a set of serialized shares to reconstruct a secret.
   *
   * Expected to be called from a transaction context.
   *
   * @param t               number of available shares
   * @param shares          buffer containing `t` shares, concatenated back to back
   * @param sharesOff       offset into the shares buffer
   * @param sharesLen       length of the shares buffer; must be a multiple of `t`
   * @param secret          output buffer for the recovered secret; large enough to store the
   *                        secret without the metadata: `(sharesLen - METADATA_SIZE) / t`
   * @param secretOff       offset into the secret buffer to start writing
   *
   * @throws `CryptoException.ILLEGAL_VALUE` if `sharesLen` is not a multiple of `t`.
   * @throws `CryptoException.ILLEGAL_VALUE` if `shares` does not contain well-formed shares,
   *    or if any attempt to recover the secret fails, such as due to a mismatched checksum
   *    indicating incorrect or corrupted share values.
   * @throws `CryptoException.ILLEGAL_USE` if `shares` contains shares from different sets,
   *    or if it contains shares that do not match a previous invocation of this method.
   */
  public short combineShares(byte t,
      byte[] shares, short sharesOff, short sharesLen,
      byte[] secret, short secretOff)
  {
    short secretLen;
    short result;
    short id;
    short i, j, k;

    // split parameters
    byte g, gt, gi, mt, mi;

    // references to x- and y-coordinate arrays during each group share iteration
    byte[] gx, gy;

    if (sharesLen == 0 || (sharesLen % t) != 0) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    secretLen = (short)(sharesLen / t - METADATA_SIZE);

    if (secretLen <= 0) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    // use the first share to establish values for common metadata
    id = Util.getShort(shares, sharesOff);
    g = getGroupCount(shares, sharesOff);
    gt = getGroupThreshold(shares, sharesOff);
    if (gt <= 0 || gt > g || g > Shamir.MAX_SHARE_COUNT) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }

    if (pendingId == 0) {
      pendingId = id;
      pendingGroupX = new Object[g];
      pendingGroupY = new Object[g];
      pendingX = new byte[gt];
      pendingY = new byte[(short)(gt * secretLen)];
      Util.arrayFillNonAtomic(pendingX, (short) 0, gt, UNUSED);
    } else if (pendingId != id) {
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }

    result = 0;

    for (i = 0; i < t; i++) {
      // verify that the share belongs to the same set
      if (id != Util.getShort(shares, sharesOff) ||
          g != getGroupCount(shares, sharesOff) ||
          gt != getGroupThreshold(shares, sharesOff)) {
        CryptoException.throwIt(CryptoException.ILLEGAL_USE);
      }

      gi = getGroupIndex(shares, sharesOff);
      mi = getMemberIndex(shares, sharesOff);
      mt = getMemberThreshold(shares, sharesOff);
      if (mi < 0 || mi >= Shamir.MAX_SHARE_COUNT) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      if (mt <= 0 || mt > Shamir.MAX_SHARE_COUNT) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }

      // advance to the start of the share value
      sharesOff += METADATA_SIZE;

      if (pendingGroupX[gi] == null) {
        pendingGroupX[gi] = new byte[mt];
        pendingGroupY[gi] = new byte[(short)(mt * secretLen)];
        Util.arrayFillNonAtomic((byte[]) pendingGroupX[gi], (short) 0, mt, UNUSED);
      }
      gx = (byte[]) pendingGroupX[gi];
      gy = (byte[]) pendingGroupY[gi];
      if (gx.length != mt || gy.length != (short)(mt * secretLen)) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }

      // find the first unused slot `j` where `0 ≤ j < t_i`
      for (j = 0; j < gx.length; j++) {
        if (gx[j] == mi) {
          // a share matching (id, gi, mi) was already recorded, skip this duplicate
          break;
        }
        if (gx[j] == UNUSED) {
          gx[j] = mi;
          Util.arrayCopy(shares, sharesOff, gy, (short)(j * secretLen), secretLen);
          break;
        }
      }
      if (j == gx.length) {
        // this group's share is already recovered, skip extraneous shares
      }
      if (j == (short)(gx.length - 1)) {
        // this group's share is ready to be recovered (have threshold member shares)
        // find the first unused slot `k` where `0 ≤ k < gt`
        for (k = 0; k < pendingX.length; k++) {
          if (pendingX[k] == gi) {
            // this group's share is already recovered, skip extraneous member shares
            break;
          }
          if (pendingX[k] == UNUSED) {
            pendingX[k] = gi;
            result = shamir.combine(mt, gx, gy, (short) 0, (short) gy.length,
                pendingY, (short)(k * secretLen));
            if (result == secretLen) {
              // recovered this group's share successfully, but not the final result
              // yet, so zero out the result variable before continuing.
              result = 0;
            } else {
              CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            break;
          }
        }
        if (k == pendingX.length) {
          // master secret is already recovered, skip extraneous shares
        }
        if (k == (short)(pendingX.length - 1)) {
          // master secret is ready to be recovered (have threshold group shares)
          result = shamir.combine(gt, pendingX, pendingY, (short) 0, (short) pendingY.length,
              secret, secretOff);
          if (result == secretLen) {
            // recovered master secret successfully
          } else {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
          }
          break;
        }
      }

      // advance to the start of the next share
      sharesOff += secretLen;
    }

    return result;
  }

  /**
   * Resets internal state, aborting any progress and deleting previously combined shares.
   *
   * Any subsequent call to `combineShares` will start without prior state.
   *
   * Expected to be called from a transaction context.
   */
  public void reset()
  {
    pendingGroupY = null;
    pendingGroupX = null;
    pendingY = null;
    pendingX = null;
    pendingId = 0;
  }

  private byte getGroupThreshold(byte[] buf, short off)
  {
    return (byte)(((buf[(short)(off + 2)] >> 4) & 0xf) + 1);
  }

  private byte getGroupCount(byte[] buf, short off)
  {
    return (byte)((buf[(short)(off + 2)] & 0xf) + 1);
  }

  private byte getGroupIndex(byte[] buf, short off)
  {
    return (byte)((buf[(short)(off + 3)] >> 4) & 0xf);
  }

  private byte getMemberThreshold(byte[] buf, short off)
  {
    return (byte)((buf[(short)(off + 3)] & 0xf) + 1);
  }

  private byte getMemberIndex(byte[] buf, short off)
  {
    return (byte)(buf[(short)(off + 4)] & 0xf);
  }

  private short serializeShare(short id, byte g, byte gt, byte gi, byte mt, byte mi,
    byte[] value, short valueOff, short valueLen,
    byte[] out, short outOff)
  {
    // these one-based values are encoded as (value - 1), with range [0 .. max-1]
    g -= 1;
    gt -= 1;
    mt -= 1;
    outOff = Util.setShort(out, outOff, id);
    out[outOff++] = (byte)(((gt & 0xf) << 4) | (g & 0xf));
    out[outOff++] = (byte)(((gi & 0xf) << 4) | (mt & 0xf));
    out[outOff++] = (byte)(mi & 0xf);
    return Util.arrayCopy(value, valueOff, out, outOff, valueLen);
  }

  private byte largestGroup(byte[] groups)
  {
    short i;
    byte t, n, max = 0;

    for (i = 0; i < (short) groups.length; i += 2) {
      t = groups[i];
      n = groups[(short)(i + 1)];
      if (t <= 0 || t > n) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      if (max < n) {
        max = n;
      }
    }
    return max;
  }
}
