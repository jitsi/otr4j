package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.security.KeyPair;
import javax.crypto.interfaces.DHPublicKey;

import junit.framework.TestCase;

import net.java.otr4j.message.encoded.RevealSignatureMessage;
import net.java.otr4j.protocol.crypto.CryptoConstants;
import net.java.otr4j.protocol.crypto.CryptoUtils;
import net.java.otr4j.utils.Utils;

import org.junit.Test;

public class RevealSignatureMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {

		// Prepare arguments.
		KeyPair dhKeyPairX = CryptoUtils.generateDHKeyPair();
		KeyPair dhKeyPairY = CryptoUtils.generateDHKeyPair();
		int keyidB = 1;
		KeyPair dsaKeyPair = CryptoUtils.generateDsaKeyPair();
		int protocolVersion = 2;

		BigInteger s = CryptoUtils.generateSecret(dhKeyPairX);

		byte[] r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);

		RevealSignatureMessage msg = new RevealSignatureMessage(
				protocolVersion, s, (DHPublicKey) dhKeyPairX.getPublic(),
				(DHPublicKey) dhKeyPairY.getPublic(), keyidB, dsaKeyPair
						.getPrivate(), dsaKeyPair.getPublic(), r);

		assertNotNull(msg);

	}

	@Test
	public void testDisassemble() {
		RevealSignatureMessage revealSignatureMessage = new RevealSignatureMessage(
				EncodedMessageTextSample.RevealSignatureMessageText);
		assertNotNull(revealSignatureMessage);
	}

}
