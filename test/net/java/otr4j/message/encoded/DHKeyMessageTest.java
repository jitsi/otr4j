package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import org.junit.Test;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.DHKeyMessage;

public class DHKeyMessageTest extends junit.framework.TestCase {

	@Test
	public void testReadObject() throws Exception {
		byte[] decodedMessage = EncodedMessageUtils
				.decodeMessage(EncodedMessageTextSample.DHKeyMessageText);
		ByteArrayInputStream bis = new ByteArrayInputStream(decodedMessage);
		
		DHKeyMessage dhKey = new DHKeyMessage();
		dhKey.readObject(bis);
		
		assertEquals(dhKey.getMessageType(), MessageType.DH_KEY);
		assertEquals(dhKey.getProtocolVersion(), 2);
		assertNotNull(dhKey.getDhPublicKey());
	}

}
