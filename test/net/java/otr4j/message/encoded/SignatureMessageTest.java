package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.security.KeyPair;
import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.protocol.crypto.CryptoUtils;

import org.junit.Test;

import junit.framework.TestCase;

public final class SignatureMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {
		// Prepare arguments.
		KeyPair dhKeyPairX = CryptoUtils.generateDHKeyPair();
		KeyPair dhKeyPairY = CryptoUtils.generateDHKeyPair();
		int keyidB = 1;
		KeyPair keyPair = CryptoUtils.generateDsaKeyPair();
		int protocolVersion = 2;

		BigInteger s = CryptoUtils.getSecretKey(dhKeyPairX, dhKeyPairY);

		byte[] cp = EncodedMessageUtils.getCp(s);
		byte[] m1p = EncodedMessageUtils.getM1p(s);
		byte[] m2p = EncodedMessageUtils.getM2p(s);
		SignatureMessage msg = new SignatureMessage(protocolVersion,
				(DHPublicKey) dhKeyPairX.getPublic(), (DHPublicKey) dhKeyPairY
						.getPublic(), keyidB, keyPair.getPrivate(), keyPair
						.getPublic(), cp, m1p, m2p);

		assertNotNull(msg);

	}

	@Test
	public void testDisassemble() {
		SignatureMessage signatureMessage = new SignatureMessage(EncodedMessageTextSample.SignatureMessageText);
		assertNotNull(signatureMessage);
	}

}
