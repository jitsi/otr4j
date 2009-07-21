package net.java.otr4j.message.unencoded;

import net.java.otr4j.message.ErrorMessage;
import junit.framework.TestCase;

public class ErrorMessageTest extends TestCase {

	public void testDisassemble() {
		ErrorMessage errorMessage = new ErrorMessage(UnencodedMessageTextSample.ErrorMessageText);
		assertNotNull(errorMessage);
	}
}
