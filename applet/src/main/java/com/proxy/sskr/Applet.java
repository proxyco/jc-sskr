/*
 * Copyright © 2023 Proxy, Inc (proxy.com)
 * Licensed under the "BSD-2-Clause Plus Patent License"
 */

package com.proxy.sskr;

import javacard.framework.*;
import javacard.security.*;

public class Applet extends javacard.framework.Applet implements AppletEvent
{
  public static final byte CLA_PROPRIETARY = (byte) 0x80;

  /**
   * Return data field back as response.
   *
   * P1       |
   * P2       |
   * Data     |
   * Response | contents of the data field
   */
  public static final byte INS_ECHO = (byte) 0x00;

  /**
   * Generate shares from our secret.
   *
   * P1       | group threshold (gt)
   * P2       | group count (g)
   * Data     | group descriptors, as a sequence of bytes (t_i, n_i, ...) for i: 1 ≤ i ≤ g
   * Response | generated shares, concatenated back to back
   */
  public static final byte INS_GENERATE_SHARES = (byte) 0x01;

  /**
   * Combine shares and return the recovered secret.
   *
   * P1       | number of shares (t)
   * P2       |
   * Data     | at least t shares, concatenated back to back
   * Response | recovered secret, or empty response of not enough shares received
   */
  public static final byte INS_COMBINE_SHARES = (byte) 0x02;

  private static final byte[] secret = new byte[] {
    (byte) 0x7d, (byte) 0xaa, (byte) 0x85, (byte) 0x12,
    (byte) 0x51, (byte) 0x00, (byte) 0x28, (byte) 0x74,
    (byte) 0xe1, (byte) 0xa1, (byte) 0x99, (byte) 0x5f,
    (byte) 0x08, (byte) 0x97, (byte) 0xe6, (byte) 0xb1
  };

  private RandomData randomSource;
  private SSKR sskr;

  public static void install(byte[] bArray, short bOffset, byte bLength)
  {
    new Applet();
  }

  public final void uninstall()
  {
    // This method is called in the moment of uninstallation.
    // Cleanup static objects, and backup any data, here.
    Crypto.releaseInstance();
  }

  public Applet()
  {
    randomSource = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    sskr = new SSKR(randomSource, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
    register();
  }

  public void process(APDU apdu)
  {
    if (selectingApplet()) {
      return;
    }

    byte[] buf = apdu.getBuffer();
    byte cla = buf[ISO7816.OFFSET_CLA];
    byte ins = buf[ISO7816.OFFSET_INS];

    apdu.setIncomingAndReceive();

    if (cla == CLA_PROPRIETARY) {
      switch (ins) {
        case INS_ECHO:
          processEcho(apdu);
          break;

        case INS_GENERATE_SHARES:
          processGenerateShares(apdu);
          break;

        case INS_COMBINE_SHARES:
          processCombineShares(apdu);
          break;

        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } else {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
  }

  private void processEcho(APDU apdu)
  {
    short lc = apdu.getIncomingLength();
    apdu.setOutgoingAndSend(apdu.getOffsetCdata(), lc);
  }

  private void processGenerateShares(APDU apdu)
  {
    byte[] buf = apdu.getBuffer();
    short off = apdu.getOffsetCdata();
    short lc = apdu.getIncomingLength();
    byte p1 = buf[ISO7816.OFFSET_P1];
    byte p2 = buf[ISO7816.OFFSET_P2];

    byte[] groups = JCSystem.makeTransientByteArray((short)(p2 * 2), JCSystem.CLEAR_ON_DESELECT);
    Util.arrayCopyNonAtomic(buf, off, groups, (short) 0, (short) groups.length);

    short len = sskr.generateShares(p1, groups, secret, (short) 0, (short) secret.length,
        buf, (short) 0);

    apdu.setOutgoingAndSend((short) 0, len);
  }

  private void processCombineShares(APDU apdu)
  {
    byte[] buf = apdu.getBuffer();
    short off = apdu.getOffsetCdata();
    short lc = apdu.getIncomingLength();
    byte p1 = buf[ISO7816.OFFSET_P1];
    byte p2 = buf[ISO7816.OFFSET_P2];

    short len = sskr.combineShares(p1, buf, off, lc, buf, (short)(off + lc));

    apdu.setOutgoingAndSend((short)(off + lc), len);
  }
}
