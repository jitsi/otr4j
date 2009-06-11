package net.java.otr4j.message.encoded;

import javax.crypto.interfaces.DHPublicKey;

import junit.framework.TestCase;
import net.java.otr4j.message.encoded.DHCommitMessage;
import net.java.otr4j.protocol.crypto.CryptoConstants;
import net.java.otr4j.protocol.crypto.CryptoUtils;
import net.java.otr4j.utils.Utils;

import org.junit.Test;

public class DHCommitMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {
		// Prepare arguments.
		DHPublicKey key = (DHPublicKey) CryptoUtils.generateDHKeyPair()
				.getPublic();
		byte[] r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);
		int protocolVersion = 2;
		byte[] keyHash = CryptoUtils.sha256Hash(key.getEncoded());

		DHCommitMessage dhCommitMessage = new DHCommitMessage(protocolVersion,
				r, key, keyHash);

		assertNotNull(dhCommitMessage);

	}

	@Test
	public void testDisassemble() {
		DHCommitMessage dhCommitMessage = new DHCommitMessage(
				EncodedMessageTextSample.DHCommitMessageText);
		assertNotNull(dhCommitMessage);
	}

}
