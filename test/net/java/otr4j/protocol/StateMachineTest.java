package net.java.otr4j.protocol;

import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrEngineImpl;
import net.java.otr4j.message.unencoded.UnencodedMessageTextSample;
import net.java.otr4j.session.SessionID;

public class StateMachineTest extends junit.framework.TestCase {

	private SessionID aliceSessionID = new SessionID("Alice@Wonderland",
			"Bob@Wonderland", "Scytale");
	private SessionID bobSessionID = new SessionID("Bob@Wonderland",
			"Alice@Wonderland", "Scytale");

	public void testReceivingMessage() throws Exception {

		DummyOTR4jListener listener = new DummyOTR4jListener(
				OtrPolicy.ALLOW_V2 | OtrPolicy.ERROR_START_AKE);

		OtrEngineImpl usAlice = new OtrEngineImpl(listener);
		OtrEngineImpl usBob = new OtrEngineImpl(listener);

		// Bob receives query, sends D-H commit.
		@SuppressWarnings("unused")
		String receivedMessage = usBob.transformReceiving(bobSessionID,
				UnencodedMessageTextSample.QueryMessage_V12);

		// Alice received D-H Commit, sends D-H key.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				listener.lastInjectedMessage);

		// Bob receives D-H Key, sends reveal signature.
		receivedMessage = usBob.transformReceiving(bobSessionID,
				listener.lastInjectedMessage);

		// Alice receives Reveal Signature, sends signature and goes secure.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				listener.lastInjectedMessage);

		// Bobs receives Signature, goes secure.
		receivedMessage = usBob.transformReceiving(bobSessionID,
				listener.lastInjectedMessage);

		// We are both secure, send encrypted message.
		String sentMessage = usAlice
				.transformSending(
						aliceSessionID,
						"Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what is that supposed to mean?");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usBob.transformReceiving(bobSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usBob
				.transformSending(bobSessionID,
						"Hey Alice, it means that our communication is encrypted and authenticated.");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usAlice.transformSending(aliceSessionID,
				"Oh, is that all?");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usBob.transformReceiving(bobSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usBob
				.transformSending(

						bobSessionID,
						"Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				sentMessage);

		// Send encrypted message.
		sentMessage = usAlice.transformSending(aliceSessionID,
				"Oh really?!");
		assertFalse(sentMessage == null || sentMessage.length() < 1);

		// Receive encrypted message.
		receivedMessage = usBob.transformReceiving(bobSessionID,
				sentMessage);

	}

}
