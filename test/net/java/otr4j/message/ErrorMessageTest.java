package net.java.otr4j.message;

import java.io.IOException;

public class ErrorMessageTest extends AbstractMessageTestCase {

	public static final String ErrorMessageText = "This is a test error.";

	public void testRead() throws IOException {
		ErrorMessage errorMessage = new ErrorMessage();
		errorMessage.readObject(MessageConstants.ERROR_HEAD + ErrorMessageText);
		assertEquals(ErrorMessageText, errorMessage.error);
	}

	public void testWrite() throws IOException {
		ErrorMessage errorMessage = new ErrorMessage(ErrorMessageText);

		String error = errorMessage.writeObject();
		assertEquals(MessageConstants.ERROR_HEAD + ErrorMessageText, error);
	}
}
