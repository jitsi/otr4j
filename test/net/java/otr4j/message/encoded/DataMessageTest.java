package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import junit.framework.TestCase;

import org.junit.Test;

import net.java.otr4j.message.encoded.DataMessage;

public class DataMessageTest extends TestCase {
	@Test
	public void testCreate() {
		// TODO Implement
	}

	@Test
	public void testReadObject() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decodedMessage = EncodedMessageUtils
				.decodeMessage(EncodedMessageTextSample.DataMessage1);

		ByteArrayInputStream bis = new ByteArrayInputStream(decodedMessage);
		DataMessage dataMessage1 = new DataMessage();
		dataMessage1.readObject(bis);

		
		assertNotNull(dataMessage1.ctr);
		assertNotNull(dataMessage1.mac);
	}
}
