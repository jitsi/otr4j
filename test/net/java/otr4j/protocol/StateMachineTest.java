package net.java.otr4j.protocol;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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

	MessageInfo miFromBob = new MessageInfo("Bob", "Alice@Wonderland", "proto");
	MessageInfo miFromAlice = new MessageInfo("Alice", "Bob@Wonderland",
			"proto");

	private static Logger logger = Logger.getLogger(StateMachine.class);

	public void testReceivingMessage() throws Exception {

		DummyOTR4jListener listener = new DummyOTR4jListener(Policy.ALLOW_V2
				| Policy.ERROR_START_AKE);

		UserState usAlice = new UserState();
		UserState usBob = new UserState();

		runAKE(listener, UnencodedMessageTextSample.QueryMessage_V12, usAlice,
				usBob);

		AliceToBob(listener, usAlice, "Hello");

		StateMachine.receivingMessage(listener, usBob, miFromAlice.user,
				miFromAlice.account, miFromAlice.protocol,
				listener.lastInjectedMessage);
		/*
		 * listener.lastInjectedMessage = null; runAKE(listener,
		 * "Hello World.");
		 * 
		 * listener.lastInjectedMessage = null; runAKE(listener,
		 * UnencodedMessageTextSample.ErrorMessageText);
		 */
	}

	private void AliceToBob(DummyOTR4jListener listener, UserState usAlice,
			String message) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, SignatureException, IOException {
		StateMachine.sendingMessage(listener, usAlice, miFromBob.user,
				miFromBob.account, miFromBob.protocol, message);
	}

	private void runAKE(DummyOTR4jListener listener, String initialMessage,
			UserState usAlice, UserState usBob) throws Exception {

		logger.debug("- RUNNING AKE.");

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
