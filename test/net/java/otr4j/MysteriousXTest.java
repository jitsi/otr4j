package net.java.otr4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import net.java.otr4j.crypto.CryptoUtils;

import org.junit.Test;

import junit.framework.TestCase;

public class MysteriousXTest extends TestCase {

	@Test
	public void testSerialization() throws IOException,
			NoSuchAlgorithmException {

		KeyPair keyPair = CryptoUtils.generateDsaKeyPair();
		BigInteger[] sig = new BigInteger[2];
		sig[0] = BigInteger.ZERO;
		sig[1] = BigInteger.ONE;

		MysteriousX x = new MysteriousX(keyPair.getPublic(), 0, sig);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(out);
		oos.writeObject(x);
		oos.close();
		
		assertTrue(out.toByteArray().length > 0);
	}
}
