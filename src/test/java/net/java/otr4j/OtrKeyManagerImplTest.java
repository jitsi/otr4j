package net.java.otr4j;

import net.java.otr4j.session.SessionID;

public class OtrKeyManagerImplTest extends junit.framework.TestCase {

	private SessionID aliceSessionID = new SessionID("Alice@Wonderland",
			"Bob@Wonderland", "Scytale");

	public void test() throws Exception {
		OtrKeyManager keyManager = new OtrKeyManagerImpl("otr.properties");
		keyManager.generateLocalKeyPair(aliceSessionID);

		keyManager.verify(aliceSessionID);
		assert (keyManager.isVerified(aliceSessionID));
	}
}
