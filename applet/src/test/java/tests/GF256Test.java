/*
 * Original adapted: https://github.com/codahale/shamir
 */

/*
 * Copyright © 2017 Coda Hale (coda.hale@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tests;

import com.proxy.sskr.GF256;

import com.licel.jcardsim.utils.ByteUtil;

import javacard.framework.*;
import javacard.security.*;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.jupiter.api.*;

public class GF256Test
{
  public GF256Test() {
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

  @Test
  void add() throws Exception
  {
    Assert.assertEquals(GF256.add((byte) 100, (byte) 30), 122);
  }

  @Test
  void sub()
  {
    Assert.assertEquals(GF256.sub((byte) 100, (byte) 30), 122);
  }

  @Test
  void mul()
  {
    Assert.assertEquals(GF256.mul((byte) 90, (byte) 21), (byte) 254);
    Assert.assertEquals(GF256.mul((byte) 133, (byte) 5), (byte) 167);
    Assert.assertEquals(GF256.mul((byte) 0, (byte) 21), (byte) 0);
    Assert.assertEquals(GF256.mul((byte) 0xb6, (byte) 0x53), (byte) 0x36);
  }

  @Test
  void div()
  {
    Assert.assertEquals(GF256.div((byte) 90, (byte) 21), (byte) 189);
    Assert.assertEquals(GF256.div((byte) 6, (byte) 55), (byte) 151);
    Assert.assertEquals(GF256.div((byte) 22, (byte) 192), (byte) 138);
    Assert.assertEquals(GF256.div((byte) 0, (byte) 192), (byte) 0);
  }

  @Test
  void mulIsCommutative()
  {
    for (short i = -128; i < 128; i++) {
      for (short j = -128; j < 128; j++) {
        Assert.assertEquals(GF256.mul((byte) i, (byte) j), GF256.mul((byte) j, (byte) i));
      }
    }
  }

  @Test
  void addIsCommutative()
  {
    for (short i = -128; i < 128; i++) {
      for (short j = -128; j < 128; j++) {
        Assert.assertEquals(GF256.add((byte) i, (byte) j), GF256.add((byte) j, (byte) i));
      }
    }
  }

  @Test
  void subIsTheInverseOfAdd()
  {
    for (short i = -128; i < 128; i++) {
      for (short j = -128; j < 128; j++) {
        Assert.assertEquals(GF256.sub(GF256.add((byte) i, (byte) j), (byte) j), i);
      }
    }
  }

  @Test
  void divIsTheInverseOfMul()
  {
    for (short i = -128; i < 128; i++) {
      for (short j = -128; j < 128; j++) {
        if (j == 0) {
          continue;
        }
        Assert.assertEquals(GF256.div(GF256.mul((byte) i, (byte) j), (byte) j), i);
      }
    }
  }

  @Test
  void mulIsTheInverseOfDiv()
  {
    for (short i = -128; i < 128; i++) {
      for (short j = -128; j < 128; j++) {
        if (j == 0) {
          continue;
        }
        Assert.assertEquals(GF256.mul(GF256.div((byte) i, (byte) j), (byte) j), i);
      }
    }
  }

  @Test
  void interpolate()
  {
    Assert.assertEquals((byte) 0, GF256.interpolate((byte) 0, new byte[] {1, 1, 2, 2, 3, 3}));
    Assert.assertEquals((byte) 30, GF256.interpolate((byte) 0, new byte[] {1, 80, 2, 90, 3, 20}));
    Assert.assertEquals((byte) 107, GF256.interpolate((byte) 0, new byte[] {1, 43, 2, 22, 3, 86}));
  }
}
