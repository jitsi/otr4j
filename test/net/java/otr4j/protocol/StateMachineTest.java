package net.java.otr4j.protocol;

import org.apache.log4j.Logger;
import net.java.otr4j.message.unencoded.UnencodedMessageTextSample;
import junit.framework.TestCase;

public class StateMachineTest extends TestCase {
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

	private static Logger logger = Logger.getLogger(StateMachine.class);

	public void testReceivingMessage() throws Exception {
		
		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2
				| Policy.ERROR_START_AKE);
		UserState usAlice = new UserState();
		UserState usBob = new UserState();
		MessageInfo miFromBob = new MessageInfo("bob", "alice@proto", "proto");
		MessageInfo miFromAlice = new MessageInfo("alice", "alice@proto",
				"proto");

		// Alice sends a query
		logger.debug("-Alice.");
		StateMachine.receivingMessage(listener, usAlice, miFromBob.user,
				miFromBob.account, miFromBob.protocol,
				UnencodedMessageTextSample.QueryMessage_V12);

		// Bob sends a D-H commit
		logger.debug("-Bob.");
		StateMachine.receivingMessage(listener, usBob, miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);

		// Alice sends D-H key
		logger.debug("-Alice.");
		StateMachine.receivingMessage(listener, usAlice, miFromBob.user,
				miFromBob.account, miFromBob.protocol,
				listener.lastInjectedMessage);

		// Bob sends reveal signature.
		logger.debug("-Bob.");
		StateMachine.receivingMessage(listener, usBob, miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);
	}

}
