package net.java.otr4j.message.unencoded;

import net.java.otr4j.message.unencoded.query.QueryMessage;
import junit.framework.TestCase;

public class QueryMessageTest extends TestCase {
	public void testDisassemble() {
		// Test query messages
		QueryMessage queryMessage_CommonRequest = new QueryMessage(UnencodedMessageTextSample.QueryMessage_CommonRequest);
		assertNotNull(queryMessage_CommonRequest);

		QueryMessage queryMessage_V1_CASE1 = new QueryMessage(UnencodedMessageTextSample.QueryMessage_V1_CASE1);
		assertNotNull(queryMessage_V1_CASE1);

		QueryMessage queryMessage_V1_CASE2 = new QueryMessage(UnencodedMessageTextSample.QueryMessage_V1_CASE2);
		assertNotNull(queryMessage_V1_CASE2);

		QueryMessage queryMessage_V2 = new QueryMessage(UnencodedMessageTextSample.QueryMessage_V2);
		assertNotNull(queryMessage_V2);

		QueryMessage queryMessage_V12 = new QueryMessage(UnencodedMessageTextSample.QueryMessage_V12);
		assertNotNull(queryMessage_V12);

		QueryMessage queryMessage_V14x = new QueryMessage(UnencodedMessageTextSample.QueryMessage_V14x);
		assertNotNull(queryMessage_V14x);

		QueryMessage queryMessage_V124x = new QueryMessage(UnencodedMessageTextSample.QueryMessage_V124x);
		assertNotNull(queryMessage_V124x);

		QueryMessage queryMessage_Bizzare = new QueryMessage(UnencodedMessageTextSample.QueryMessage_Bizzare);
		assertNotNull(queryMessage_Bizzare);
	}

}
