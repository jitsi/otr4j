package net.java.otr4j.message;

import java.io.IOException;
import java.util.Vector;

public class QueryMessageTest extends AbstractMessageTestCase {

	// A bizarre claim that Alice would like to start an OTR conversation, but
	// is unwilling to speak any version of the protocol
	public static final String QueryMessage_Bizzare = "?OTRv?";
	// Version 1 only
	public static final String QueryMessage_V1_CASE1 = "?OTR?";
	// Also version 1 only
	public static final String QueryMessage_V1_CASE2 = "?OTR?v?";
	// Version 2 only
	public static final String QueryMessage_V2 = "?OTRv2?";
	// Version 1 and 2
	public static final String QueryMessage_V12 = "?OTR?v2?";
	// Version 2, and hypothetical future versions identified by "4" and "x"
	public static final String QueryMessage_V14x = "?OTRv24x?";
	// Versions 1, 2, and hypothetical future versions identified by "4" and "x"
	public static final String QueryMessage_V124x = "?OTR?v24x?";
	public static final String QueryMessage_CommonRequest = "?OTR?v2? Bob has requested an Off-the-Record private conversation &lt;http://otr.cypherpunks.ca/&gt;.  However, you do not have a plugin to support that. See http://otr.cypherpunks.ca/ for more information.";

	public void testRead() throws IOException {
		QueryMessage qm = new QueryMessage();
		qm.readObject(QueryMessage_V12);

		Vector<Integer> versions = qm.getVersions();

		assertTrue(versions.size() == 2 && versions.contains(1)
				&& versions.contains(2));
	}

	public void testWrite() throws IOException {
		Vector<Integer> versions = new Vector<Integer>();
		versions.add(1);
		versions.add(2);

		QueryMessage qm = new QueryMessage(versions);
		String result = qm.writeObject();

		assertTrue(result.startsWith("?OTR?v2?"));
		
		versions.clear();
		versions.add(2);
		qm = new QueryMessage(versions);
		result = qm.writeObject();

		assertTrue(result.startsWith("?OTRv2?"));
	}
}
