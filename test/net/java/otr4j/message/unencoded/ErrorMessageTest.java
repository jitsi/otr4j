package net.java.otr4j.message.unencoded;

public class ErrorMessageTest extends UnencodedMessageTestBase {

	private static String ErrorMessageText = "?OTR Error:This is a nasty error.";

	@Override
	public void testDisassemble() {
		ErrorMessage errorMessage = ErrorMessage.disassemble(ErrorMessageText);
		assertNotNull(errorMessage);
	}
}
