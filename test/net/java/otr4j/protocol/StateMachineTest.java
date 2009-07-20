package net.java.otr4j.protocol;

import net.java.otr4j.Policy;
import net.java.otr4j.UserState;
import net.java.otr4j.Utils;
import net.java.otr4j.message.unencoded.UnencodedMessageTextSample;

public class StateMachineTest extends junit.framework.TestCase {
	class MessageInfo {
		public MessageInfo(String user, String account, String protocol) {
			this.user = user;
			this.account = account;
			this.protocol = protocol;
		}

		public String account;
		public String user;
		public String protocol;
	}

	private MessageInfo miFromBob = new MessageInfo("Bob", "Alice@Wonderland",
			"Scytale");
	private MessageInfo miFromAlice = new MessageInfo("Alice",
			"Bob@Wonderland", "Scytale");

	public void testReceivingMessage() throws Exception {

		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2
				| Policy.ERROR_START_AKE);

		UserState usAlice = new UserState(listener);
		UserState usBob = new UserState(listener);

		// Bob receives query, sends D-H commit.
		@SuppressWarnings("unused")
		String receivedMessage = usBob.handleReceivingMessage(miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				UnencodedMessageTextSample.QueryMessage_V12);

		// Alice received D-H Commit, sends D-H key.
		receivedMessage = usAlice.handleReceivingMessage(miFromBob.user,
				miFromBob.account, miFromBob.protocol,
				listener.lastInjectedMessage);

		// Bob receives D-H Key, sends reveal signature.
		receivedMessage = usBob.handleReceivingMessage(miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);

		// Alice receives Reveal Signature, sends signature and goes secure.
		receivedMessage = usAlice.handleReceivingMessage(miFromBob.user,
				miFromBob.account, miFromBob.protocol,
				listener.lastInjectedMessage);

		// Bobs receives Signature, goes secure.
		receivedMessage = usBob.handleReceivingMessage(miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);

		// We are both secure, send encrypted message.
		String sentMessage = usAlice
				.handleSendingMessage(

						miFromBob.user,
						miFromBob.account,
						miFromBob.protocol,
						"Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what is that supposed to mean?");
		assertFalse(Utils.IsNullOrEmpty(sentMessage));

		// Receive encrypted message.
		receivedMessage = usBob.handleReceivingMessage(miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol, sentMessage);

		// Send encrypted message.
		sentMessage = usBob
				.handleSendingMessage(miFromAlice.user, miFromAlice.account,
						miFromAlice.protocol,
						"Hey Alice, it means that our communication is encrypted and authenticated.");
		assertFalse(Utils.IsNullOrEmpty(sentMessage));

		// Receive encrypted message.
		receivedMessage = usAlice.handleReceivingMessage(miFromBob.user,
				miFromBob.account, miFromBob.protocol, sentMessage);

		// Send encrypted message.
		sentMessage = usAlice.handleSendingMessage(miFromBob.user,
				miFromBob.account, miFromBob.protocol, "Oh, is that all?");
		assertFalse(Utils.IsNullOrEmpty(sentMessage));

		// Receive encrypted message.
		receivedMessage = usBob.handleReceivingMessage(miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol, sentMessage);

		// Send encrypted message.
		sentMessage = usBob
				.handleSendingMessage(

						miFromAlice.user,
						miFromAlice.account,
						miFromAlice.protocol,
						"Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.");
		assertFalse(Utils.IsNullOrEmpty(sentMessage));

		// Receive encrypted message.
		receivedMessage = usAlice.handleReceivingMessage(miFromBob.user,
				miFromBob.account, miFromBob.protocol, sentMessage);

		// Send encrypted message.
		sentMessage = usAlice.handleSendingMessage(miFromBob.user,
				miFromBob.account, miFromBob.protocol, "Oh really?!");
		assertFalse(Utils.IsNullOrEmpty(sentMessage));

		// Receive encrypted message.
		receivedMessage = usBob.handleReceivingMessage(miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol, sentMessage);

	}

}
