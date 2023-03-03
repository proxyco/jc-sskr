/*
 * Copyright © 2023 Proxy, Inc (proxy.com)
 * Licensed under the "BSD-2-Clause Plus Patent License"
 */

package com.proxy.sskr;

import javacard.framework.*;

public class Applet extends javacard.framework.Applet
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

  public static void install(byte[] bArray, short bOffset, byte bLength)
  {
    new Applet();
  }

  public Applet()
  {
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
}
