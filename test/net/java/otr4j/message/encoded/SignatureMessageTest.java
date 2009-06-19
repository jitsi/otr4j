package net.java.otr4j.message.encoded;

import org.junit.Test;
import junit.framework.TestCase;

public final class SignatureMessageTest extends TestCase {

	@Test
	public void testDisassemble() {
		SignatureMessage signatureMessage = new SignatureMessage(
				EncodedMessageTextSample.SignatureMessageText);
		assertNotNull(signatureMessage);
	}

}
