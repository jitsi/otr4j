package net.java.otr4j.protocol;

import net.java.otr4j.Policy;
import net.java.otr4j.StateMachine;
import net.java.otr4j.UserState;
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
			"proto");
	private MessageInfo miFromAlice = new MessageInfo("Alice",
			"Bob@Wonderland", "proto");

	public void testReceivingMessage() throws Exception {

		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2
				| Policy.ERROR_START_AKE);

		UserState usAlice = new UserState();
		UserState usBob = new UserState();

		// Bob receives query, sends D-H commit.
		@SuppressWarnings("unused")
		String receivedMessage = StateMachine.receivingMessage(listener, usBob,
				miFromAlice.user, miFromAlice.account, miFromAlice.protocol,
				UnencodedMessageTextSample.QueryMessage_V12);

		// Alice received D-H Commit, sends D-H key.
		receivedMessage = StateMachine.receivingMessage(listener, usAlice,
				miFromBob.user, miFromBob.account, miFromBob.protocol,
				listener.lastInjectedMessage);

		// Bob receives D-H Key, sends reveal signature.
		receivedMessage = StateMachine.receivingMessage(listener, usBob,
				miFromAlice.user, miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);

		// Alice receives Reveal Signature, sends signature and goes secure.
		receivedMessage = StateMachine.receivingMessage(listener, usAlice,
				miFromBob.user, miFromBob.account, miFromBob.protocol,
				listener.lastInjectedMessage);

		// Bobs receives Signature, goes secure.
		receivedMessage = StateMachine.receivingMessage(listener, usBob,
				miFromAlice.user, miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);

		// We are both secure, send encrypted message.
		String sentMessage = StateMachine.sendingMessage(listener, usAlice,
				miFromBob.user, miFromBob.account, miFromBob.protocol,
				"Hello Bob, we are talking encrypted now.");

		// Receive encrypted message.
		receivedMessage = StateMachine.receivingMessage(listener, usBob,
				miFromAlice.user, miFromAlice.account, miFromAlice.protocol,
				sentMessage);

		// Send encrypted message.
		sentMessage = StateMachine
				.sendingMessage(
						listener,
						usBob,
						miFromAlice.user,
						miFromAlice.account,
						miFromAlice.protocol,
						"Great, let's exchange some messages and see if that works as expected. Let's count to 3.");

		// Receive encrypted message.
		receivedMessage = StateMachine.receivingMessage(listener, usAlice,
				miFromBob.user, miFromBob.account, miFromBob.protocol,
				sentMessage);

		// Send encrypted message.
		sentMessage = StateMachine.sendingMessage(listener, usAlice,
				miFromBob.user, miFromBob.account, miFromBob.protocol, "1");

		// Receive encrypted message.
		receivedMessage = StateMachine.receivingMessage(listener, usBob,
				miFromAlice.user, miFromAlice.account, miFromAlice.protocol,
				sentMessage);

		// Send encrypted message.
		sentMessage = StateMachine.sendingMessage(listener, usBob,
				miFromAlice.user, miFromAlice.account, miFromAlice.protocol,
				"2");

		// Receive encrypted message.
		receivedMessage = StateMachine.receivingMessage(listener, usAlice,
				miFromBob.user, miFromBob.account, miFromBob.protocol,
				sentMessage);

		// Send encrypted message.
		sentMessage = StateMachine.sendingMessage(listener, usAlice,
				miFromBob.user, miFromBob.account, miFromBob.protocol, "3");

		// Receive encrypted message.
		receivedMessage = StateMachine.receivingMessage(listener, usBob,
				miFromAlice.user, miFromAlice.account, miFromAlice.protocol,
				sentMessage);

	}

}
