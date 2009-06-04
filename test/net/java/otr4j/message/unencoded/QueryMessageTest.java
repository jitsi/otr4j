package net.java.otr4j.message.unencoded;

public class QueryMessageTest extends UnencodedMessageTestBase {

	private static String QueryMessage_CommonRequest = "?OTR?v2? Bob has requested an Off-the-Record private conversation &lt;http://otr.cypherpunks.ca/&gt;.  However, you do not have a plugin to support that. See http://otr.cypherpunks.ca/ for more information.";

	// A bizarre claim that Alice would like to start an OTR conversation, but
	// is unwilling to speak any version of the protocol
	private static String QueryMessage_Bizzare = "?OTRv?";

	// Version 1 only
	private static String QueryMessage_V1_CASE1 = "?OTR?";

	// Also version 1 only
	private static String QueryMessage_V1_CASE2 = "?OTR?v?";

	// Version 2 only
	private static String QueryMessage_V2 = "?OTRv2?";

	// Version 1 and 2
	private static String QueryMessage_V12 = "?OTR?v2?";

	// Version 2, and hypothetical future versions identified by "4" and "x"
	private static String QueryMessage_V14x = "?OTRv24x?";

	// Versions 1, 2, and hypothetical future versions identified by "4" and "x"
	private static String QueryMessage_V124x = "?OTR?v24x?";

	@Override
	public void testDisassemble() {
		// Test query messages
		QueryMessage queryMessage_CommonRequest = QueryMessage.disassemble(QueryMessage_CommonRequest);
		assertNotNull(queryMessage_CommonRequest);

		QueryMessage queryMessage_V1_CASE1 = QueryMessage.disassemble(QueryMessage_V1_CASE1);
		assertNotNull(queryMessage_V1_CASE1);

		QueryMessage queryMessage_V1_CASE2 = QueryMessage.disassemble(QueryMessage_V1_CASE2);
		assertNotNull(queryMessage_V1_CASE2);

		QueryMessage queryMessage_V2 = QueryMessage.disassemble(QueryMessage_V2);
		assertNotNull(queryMessage_V2);

		QueryMessage queryMessage_V12 = QueryMessage.disassemble(QueryMessage_V12);
		assertNotNull(queryMessage_V12);

		QueryMessage queryMessage_V14x = QueryMessage.disassemble(QueryMessage_V14x);
		assertNotNull(queryMessage_V14x);

		QueryMessage queryMessage_V124x = QueryMessage.disassemble(QueryMessage_V124x);
		assertNotNull(queryMessage_V124x);

		QueryMessage queryMessage_Bizzare = QueryMessage.disassemble(QueryMessage_Bizzare);
		assertNotNull(queryMessage_Bizzare);
	}

}
