package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import net.java.otr4j.message.MessageType;

import org.junit.Test;

public class DHCommitMessageTest extends junit.framework.TestCase {

	@Test
	public void testReadObject() throws IOException {
		
		byte[] decodedMessage = EncodedMessageUtils
				.decodeMessage(EncodedMessageTextSample.DHCommitMessageText);
		
		ByteArrayInputStream bis = new ByteArrayInputStream(decodedMessage);
		DHCommitMessage dhCommit = new DHCommitMessage();
		dhCommit.readObject(bis);
		
		assertEquals(dhCommit.getMessageType(), MessageType.DH_COMMIT);
		assertEquals(dhCommit.getProtocolVersion(), 2);
		assertNotNull(dhCommit.getDhPublicKeyEncrypted());
		assertNotNull(dhCommit.getDhPublicKeyHash());
	}
}
