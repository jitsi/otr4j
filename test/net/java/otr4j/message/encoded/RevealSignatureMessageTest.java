package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import junit.framework.TestCase;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.signature.RevealSignatureMessage;

import org.junit.Test;

public class RevealSignatureMessageTest extends TestCase {

	@Test
	public void testReadObject() throws IOException {
		byte[] decodedMessage = EncodedMessageUtils
				.decodeMessage(EncodedMessageTextSample.RevealSignatureMessageText);
		ByteArrayInputStream bis = new ByteArrayInputStream(decodedMessage);

		RevealSignatureMessage revealSignature = new RevealSignatureMessage();
		revealSignature.readObject(bis);
		
		assertEquals(revealSignature.getMessageType(), MessageType.REVEALSIG);
		assertEquals(revealSignature.getProtocolVersion(), 2);
		assertNotNull(revealSignature.getXEncrypted());
		assertNotNull(revealSignature.getXEncryptedMAC());
		assertNotNull(revealSignature.getRevealedKey());
	}

}
