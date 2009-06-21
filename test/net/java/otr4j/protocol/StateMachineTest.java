package net.java.otr4j.protocol;

import org.apache.log4j.Logger;

import net.java.otr4j.Policy;
import net.java.otr4j.StateMachine;
import net.java.otr4j.UserState;
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
	
	public void testReceivingMessage_2() throws Exception {
		
		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2
				| Policy.ERROR_START_AKE);

		runAKE(listener, UnencodedMessageTextSample.QueryMessage_V12);
		
		listener.lastInjectedMessage = null;
		runAKE(listener, "Hello World.");
		
		listener.lastInjectedMessage = null;
		runAKE(listener, UnencodedMessageTextSample.ErrorMessageText);
	}

	private void runAKE(DummyOTR4jListener listener, String initialMessage)
			throws Exception {

		logger.debug("- RUNNING AKE.");
		
		UserState usAlice = new UserState();
		UserState usBob = new UserState();
		MessageInfo miFromBob = new MessageInfo("Bob", "Alice@Wonderland",
				"proto");
		MessageInfo miFromAlice = new MessageInfo("Alice", "Bob@Wonderland",
				"proto");

		StateMachine.receivingMessage(listener, usBob, miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol, initialMessage);

		StateMachine.receivingMessage(listener, usAlice, miFromBob.user,
				miFromBob.account, miFromBob.protocol,
				listener.lastInjectedMessage);

		StateMachine.receivingMessage(listener, usBob, miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);

		StateMachine.receivingMessage(listener, usAlice, miFromBob.user,
				miFromBob.account, miFromBob.protocol,
				listener.lastInjectedMessage);

		StateMachine.receivingMessage(listener, usBob, miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);
	}

}
