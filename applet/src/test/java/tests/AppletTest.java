/*
 * Copyright © 2023 Proxy, Inc (proxy.com)
 * Licensed under the "BSD-2-Clause Plus Patent License"
 */

package tests;

import cardTools.CardType;

import com.proxy.sskr.Applet;

import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Example applet funtionality tests.
 */
public class AppletTest extends BaseTest
{
  public AppletTest()
  {
    appletToSimulate = Applet.class;

    // Change card type here if you want to use physical card
    // setCardType(CardType.PHYSICAL);
    // setCardType(CardType.REMOTE);
    setCardType(CardType.JCARDSIMLOCAL);
  }

  @BeforeAll
  public static void setUpClass() throws Exception {
  }

  @AfterAll
  public static void tearDownClass() throws Exception {
  }

  @BeforeEach
  public void setUpMethod() throws Exception {
  }

  @AfterEach
  public void tearDownMethod() throws Exception {
  }

  // Example test
  @Test
  public void echo() throws Exception {
    final CommandAPDU cmd = new CommandAPDU(0x80, 0x00, 0, 0, new byte[] {0x42});
    final ResponseAPDU responseAPDU = connect().transmit(cmd);
    Assert.assertNotNull(responseAPDU);
    Assert.assertEquals(0x9000, responseAPDU.getSW());
    Assert.assertEquals(1, responseAPDU.getData().length);
  }
}
