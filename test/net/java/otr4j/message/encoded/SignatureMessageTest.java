package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.signature.SignatureMessage;

import org.junit.Test;
import junit.framework.TestCase;

public final class SignatureMessageTest extends TestCase {

	@Test
	public void testReadObject() throws IOException {
		byte[] decodedMessage = EncodedMessageUtils
				.decodeMessage(EncodedMessageTextSample.SignatureMessageText);
		ByteArrayInputStream bis = new ByteArrayInputStream(decodedMessage);
		SignatureMessage signature = new SignatureMessage();
		signature.readObject(bis);
		
		assertEquals(signature.messageType, MessageType.SIGNATURE);
		assertEquals(signature.protocolVersion, 2);
		assertNotNull(signature.xEncrypted);
		assertNotNull(signature.xEncryptedMAC);
	}

}
