package net.java.otr4j.protocol;

import org.apache.log4j.Logger;

import net.java.otr4j.message.encoded.EncodedMessageTextSample;
import net.java.otr4j.message.unencoded.UnencodedMessageTextSample;
import junit.framework.TestCase;

public class StateMachineTest extends TestCase {
	private static Logger logger = Logger.getLogger(StateMachine.class);
	private static final String user = "Superman";
	private static final String account = "LoisLane@Metropolis";
	private static final String protocol = "gtalk";
	private static final UserState userState = new UserState();

	public void testReceivingPlainTextMessage() throws Exception {
		/*
		 * StateMachine.receivingMessage(listener, userState, user, account,
		 * protocol, "");
		 */
	}

	public void testReceivingErrorMessage() throws Exception {
		logger.debug("-");
		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2 | Policy.ERROR_START_AKE);
		StateMachine.receivingMessage(listener, userState, user, account,
				protocol, UnencodedMessageTextSample.ErrorMessageText);
	}

	public void testReceivingQueryMessage() throws Exception {
		logger.debug("-");
		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2);
		StateMachine.receivingMessage(listener, userState, user, account,
				protocol, UnencodedMessageTextSample.QueryMessage_V12);
	}

	public void testReceivingDHCommitMessage() throws Exception {
		logger.debug("-");
		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2);
		StateMachine.receivingMessage(listener, userState, user, account,
				protocol, EncodedMessageTextSample.DHCommitMessageText);
	}

	public void testReceivingDHKeyMessage() throws Exception {
		logger.debug("-");
		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2);
		StateMachine.receivingMessage(listener, userState, user, account,
				protocol, EncodedMessageTextSample.DHKeyMessageText);
	}

}
