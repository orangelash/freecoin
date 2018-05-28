/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sss;

import java.security.SecureRandom;
import java.util.Random;


public final class RandomString
{

  /* Assign a string that contains the set of characters you allow. */
  private static final String symbols = "ABCDEFGJKLMNPRSTUVWXYZ0123456789"; 

  private final Random random = new SecureRandom();

  private final char[] buf;

  public RandomString(int length)
  {
    if (length < 1)
      throw new IllegalArgumentException("length < 1: " + length);
    buf = new char[length];
  }

  public String nextString()
  {
    for (int idx = 0; idx < buf.length; ++idx) 
      buf[idx] = symbols.charAt(random.nextInt(symbols.length()));
    return new String(buf);
  }

}
