package net.java.otr4j.message.encoded;

import junit.framework.TestCase;
import net.java.otr4j.message.encoded.signature.RevealSignatureMessage;

import org.junit.Test;

public class RevealSignatureMessageTest extends TestCase {

	@Test
	public void testDisassemble() {
		RevealSignatureMessage revealSignatureMessage = new RevealSignatureMessage(
				EncodedMessageTextSample.RevealSignatureMessageText);
		assertNotNull(revealSignatureMessage);
	}

}
