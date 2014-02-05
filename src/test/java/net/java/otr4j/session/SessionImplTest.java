package net.java.otr4j.session;

import java.util.logging.Logger;

import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyImpl;
import org.junit.Before;

public class SessionImplTest extends junit.framework.TestCase {

	private static Logger logger = Logger.getLogger(SessionImplTest.class
			.getName());

	private DummyServer server;
	private DummyClient alice;
	private DummyClient bob;

	@Before
	public void setUp() throws Exception {

		bob = new DummyClient();
		bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		alice = new DummyClient();
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		server = new DummyServer();
		alice.connect("Alice@Wonderland", server);
		bob.connect("Bob@Wonderland", server);

	}

	public void testQueryStart() throws Exception {

		bob.send(alice.getAccount(), "<p>?OTRv23?\n" +
				"<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n" +
				"See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>");

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.endSession();
		alice.endSession();
	}

	public void testForcedStart() throws Exception {

		bob.secureSession(alice.getAccount());

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(server.getLastMesasge()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.endSession();
		alice.endSession();
	}

	public void testPlaintext() throws Exception {

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (!msg.equals(server.getLastMesasge()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");

		if (!msg.equals(server.getLastMesasge()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");

		if (!msg.equals(server.getLastMesasge()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");

		if (!msg.equals(server.getLastMesasge()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");

		if (!msg.equals(server.getLastMesasge()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.endSession();
		alice.endSession();
	}
}
