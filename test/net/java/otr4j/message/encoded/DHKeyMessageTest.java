package net.java.otr4j.message.encoded;

import java.security.KeyPair;

import javax.crypto.interfaces.DHPublicKey;

import org.junit.Test;

import junit.framework.TestCase;

import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.encoded.DHKeyMessage;

public class DHKeyMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {

		// Prepare parameters.
		KeyPair keyPair = CryptoUtils.generateDHKeyPair();
		int protocolVersion = 2;

		DHKeyMessage dhKeyMessage = new DHKeyMessage(protocolVersion,
				(DHPublicKey) keyPair.getPublic());

		assertNotNull(dhKeyMessage);
	}

	@Test
	public void testDisassemble() throws Exception {
		DHKeyMessage dhKeyMessage = new DHKeyMessage(EncodedMessageTextSample.DHKeyMessageText);
		assertNotNull(dhKeyMessage);
	}

}
