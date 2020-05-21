package net.java.otr4j.crypto;

import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for Socialist Millionaire Protocol.
 *
 * @author Danny van Heumen
 */
public class SMTest {

    @Test
    public void testCheckGroupElemValid() throws SM.SMException {
        assertFalse(SM.checkGroupElem(BigInteger.TEN));
    }

    @Test
    public void testCheckGroupElemJustValidLowerBound() throws SM.SMException {
        assertFalse(SM.checkGroupElem(BigInteger.valueOf(2l)));
    }

    @Test
    public void testCheckGroupElemTooSmall() throws SM.SMException {
        assertTrue(SM.checkGroupElem(BigInteger.ONE));
    }

    @Test
    public void testCheckGroupElemJustValidUpperBound() throws SM.SMException {
        assertFalse(SM.checkGroupElem(SM.MODULUS_MINUS_2));
    }

    @Test
    public void testCheckGroupElemTooLarge() throws SM.SMException {
        assertTrue(SM.checkGroupElem(SM.MODULUS_MINUS_2.add(BigInteger.ONE)));
    }

    @Test
    public void testCheckExponValid() throws SM.SMException {
        assertFalse(SM.checkExpon(BigInteger.TEN));
    }

    @Test
    public void testCheckExponJustValidLowerBound() throws SM.SMException {
        assertFalse(SM.checkExpon(BigInteger.ONE));
    }

    @Test
    public void testCheckExponTooSmall() throws SM.SMException {
        assertTrue(SM.checkExpon(BigInteger.ZERO));
    }

    @Test
    public void testCheckExponJustValidUpperBound() throws SM.SMException {
        assertFalse(SM.checkExpon(SM.ORDER_S.subtract(BigInteger.ONE)));
    }

    @Test
    public void testCheckExponTooLarge() throws SM.SMException {
        assertTrue(SM.checkExpon(SM.ORDER_S));
    }
}
