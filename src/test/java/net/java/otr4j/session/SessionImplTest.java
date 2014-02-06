package net.java.otr4j.session;

import java.util.logging.Logger;

import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrPolicyImpl;

public class SessionImplTest extends junit.framework.TestCase {

	private static Logger logger = Logger.getLogger(SessionImplTest.class
			.getName());

	public void testMultipleSessions() throws Exception {
		DummyClient bob1 = new DummyClient("Bob@Wonderland");
		bob1.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient bob2 = new DummyClient("Bob@Wonderland");
		bob2.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient bob3 = new DummyClient("Bob@Wonderland");
		bob3.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob1.connect(server);
		bob2.connect(server);
		bob3.connect(server);

		bob1.send(alice.getAccount(), "<p>?OTRv23?\n" +
				"<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n" +
				"See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>");

		String msg;

		alice.send(bob1.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob1.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob2.send(alice.getAccount(), msg = "?OTRv23? Message from another client !");
		bob2.send(alice.getAccount(), msg = "This should be encrypted !");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob3.send(alice.getAccount(), msg = "?OTRv23? Another message from another client !!");
		bob3.send(alice.getAccount(), msg = "This should be encrypted !");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob1.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob1.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob1.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob1.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob1.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob1.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob1.endSession();
		alice.endSession();
	}

	public void testQueryStart() throws Exception {
		DummyClient bob = new DummyClient("Bob@Wonderland");
		bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);

		bob.send(alice.getAccount(), "<p>?OTRv23?\n" +
				"<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n" +
				"See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>");

		if (bob.getSession().getSessionStatus() != SessionStatus.ENCRYPTED
				|| alice.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
			fail("The session is not encrypted.");

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.endSession();
		alice.endSession();
	}

	public void testForcedStart() throws Exception {
		DummyClient bob = new DummyClient("Bob@Wonderland");
		bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);

		bob.secureSession(alice.getAccount());

		if (bob.getSession().getSessionStatus() != SessionStatus.ENCRYPTED
				|| alice.getSession().getSessionStatus() != SessionStatus.ENCRYPTED)
			fail("The session is not encrypted.");

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");
		if (msg.equals(server.getLastMessage()))
			fail("Message has been transferred unencrypted.");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.endSession();
		alice.endSession();
	}

	public void testPlaintext() throws Exception {
		DummyClient bob = new DummyClient("Bob@Wonderland");
		bob.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		DummyClient alice = new DummyClient("Alice@Wonderland");
		alice.setPolicy(new OtrPolicyImpl(OtrPolicy.ALLOW_V2 | OtrPolicy.ALLOW_V3
				| OtrPolicy.ERROR_START_AKE));

		Server server = new PriorityServer();
		alice.connect(server);
		bob.connect(server);

		String msg;

		alice.send(bob.getAccount(), msg = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?");

		if (bob.getSession().getSessionStatus() != SessionStatus.PLAINTEXT
				|| alice.getSession().getSessionStatus() != SessionStatus.PLAINTEXT)
			fail("The session is not plaintext.");

		if (!msg.equals(server.getLastMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Hey Alice, it means that our communication is encrypted and authenticated.");

		if (!msg.equals(server.getLastMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh, is that all?");

		if (!msg.equals(server.getLastMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.send(alice.getAccount(), msg = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");

		if (!msg.equals(server.getLastMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(alice.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		alice.send(bob.getAccount(), msg = "Oh really?! pouvons-nous parler en français?");

		if (!msg.equals(server.getLastMessage()))
			fail("Message has been altered (but it shouldn't).");

		if (!msg.equals(bob.getReceivedMessage()))
			fail("Received message is different from the sent message.");

		bob.endSession();
		alice.endSession();
	}
}
