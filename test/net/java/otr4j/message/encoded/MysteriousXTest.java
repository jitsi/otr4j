package net.java.otr4j.message.encoded;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import net.java.otr4j.Utils;
import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.encoded.MysteriousX;

import org.junit.Test;

import junit.framework.TestCase;

public class MysteriousXTest extends TestCase {

	@Test
	public void testSerialization() throws IOException,
			NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException {

		KeyPair keyPair = CryptoUtils.generateDsaKeyPair();
		byte[] signature = Utils.getRandomBytes(3);

		MysteriousX x = new MysteriousX(keyPair.getPublic(), 0, signature);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			x.writeObject(out);
		} catch (IOException ex) {
			// Signature is not valid.
		} finally {
			out.close();
		}
	}
}
