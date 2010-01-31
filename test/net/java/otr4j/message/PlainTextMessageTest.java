package net.java.otr4j.message;

import java.io.IOException;
import java.util.Vector;

import net.java.otr4j.io.messages.MessageConstants;
import net.java.otr4j.io.messages.PlainTextMessage;

public class PlainTextMessageTest extends AbstractMessageTestCase {

	private static final String plaintextMessage = "Hello There. ";

	public void testRead() throws IOException {
		PlainTextMessage plainText = new PlainTextMessage();
		plainText.readObject(plaintextMessage + MessageConstants.BASE
				+ MessageConstants.V2);

		assertEquals(plaintextMessage, plainText.getCleanText());
		assertTrue(plainText.getVersions().contains(2));
	}

	public void testWrite() throws IOException {
		Vector<Integer> versions = new Vector<Integer>();
		versions.add(2);

		PlainTextMessage plainText = new PlainTextMessage(plaintextMessage,
				versions);

		String result = plainText.writeObject();

		assertEquals(plaintextMessage + MessageConstants.BASE
				+ MessageConstants.V2, result);
	}
}
