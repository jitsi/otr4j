package net.java.otr4j.protocol;

import net.java.otr4j.PolicyConstants;
import net.java.otr4j.UserState;
import net.java.otr4j.message.unencoded.UnencodedMessageTextSample;
import net.java.otr4j.session.SessionID;

public class StateMachineTest extends junit.framework.TestCase {

	private SessionID aliceSessionID = new SessionID("Alice@Wonderland",
			"Bob@Wonderland", "Scytale");
	private SessionID bobSessionID = new SessionID("Bob@Wonderland",
			"Alice@Wonderland", "Scytale");

	public void testReceivingMessage() throws Exception {

		DummyOTR4jListener listener = new DummyOTR4jListener(
				PolicyConstants.ALLOW_V2 | PolicyConstants.ERROR_START_AKE);

		UserState usAlice = new UserState(listener);
		UserState usBob = new UserState(listener);

		// Bob receives query, sends D-H commit.
		@SuppressWarnings("unused")
		String receivedMessage = usBob.handleReceivingMessage(bobSessionID,
				UnencodedMessageTextSample.QueryMessage_V12);

		// Alice received D-H Commit, sends D-H key.
		receivedMessage = usAlice.handleReceivingMessage(aliceSessionID,
				listener.lastInjectedMessage);

		// Bob receives D-H Key, sends reveal signature.
		receivedMessage = usBob.handleReceivingMessage(bobSessionID,
				listener.lastInjectedMessage);

		// Alice receives Reveal Signature, sends signature and goes secure.
		receivedMessage = usAlice.handleReceivingMessage(aliceSessionID,
				listener.lastInjectedMessage);

		// Bobs receives Signature, goes secure.
		receivedMessage = usBob.handleReceivingMessage(bobSessionID,
				listener.lastInjectedMessage);

		// We are both secure, send encrypted message.
		String sentMessage = usAlice
				.handleSendingMessage(
						aliceSessionID,
						"Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what is that supposed to mean?");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usBob.handleReceivingMessage(bobSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usBob
				.handleSendingMessage(bobSessionID,
						"Hey Alice, it means that our communication is encrypted and authenticated.");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usAlice.handleReceivingMessage(aliceSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usAlice.handleSendingMessage(aliceSessionID,
				"Oh, is that all?");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usBob.handleReceivingMessage(bobSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usBob
				.handleSendingMessage(

						bobSessionID,
						"Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usAlice.handleReceivingMessage(aliceSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usAlice.handleSendingMessage(aliceSessionID,
				"Oh really?!");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usBob.handleReceivingMessage(bobSessionID,
				sentMessage);

	}

}
