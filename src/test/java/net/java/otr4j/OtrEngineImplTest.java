package net.java.otr4j;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrEngineImpl;
import net.java.otr4j.OtrPolicyImpl;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;

public class OtrEngineImplTest extends junit.framework.TestCase {

	private SessionID aliceSessionID = new SessionID("Alice@Wonderland",
			"Bob@Wonderland", "Scytale");
	private SessionID bobSessionID = new SessionID("Bob@Wonderland",
			"Alice@Wonderland", "Scytale");

	private static Logger logger = Logger.getLogger(OtrEngineImplTest.class
			.getName());

	class DummyOtrEngineHost implements OtrEngineHost {

		public DummyOtrEngineHost(OtrPolicy policy) {
			this.policy = policy;
		}

		private OtrPolicy policy;
		public String lastInjectedMessage;

		public OtrPolicy getSessionPolicy(SessionID ctx) {
			return this.policy;
		}

		public void injectMessage(SessionID sessionID, String msg) {

			this.lastInjectedMessage = msg;
			String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10)
					+ "..." : msg;
			logger.finest("IM injects message: " + msgDisplay);
		}

		public void smpError(SessionID sessionID, int tlvType, boolean cheated)
				throws OtrException{
			logger.severe("SM verification error with user: " + sessionID);
		}

		public void smpAborted(SessionID sessionID) throws OtrException {
			logger.severe("SM verification has been aborted by user: "
					+ sessionID);
		}

		public void finishedSessionMessage(SessionID sessionID) throws OtrException {
			logger.severe("SM session was finished. You shouldn't send messages to: "
					+ sessionID);
		}

		public void requireEncryptedMessage(SessionID sessionID, String msgText)
				throws OtrException {
			logger.severe("Message can't be sent while encrypted session is not established: "
					+ sessionID);
		}

		public void unreadableMessageReceived(SessionID sessionID)
				throws OtrException {
			logger.warning("Unreadable message received from: " + sessionID);
		}

		public void unencryptedMessageReceived(SessionID sessionID, String msg)
				throws OtrException {
			logger.warning("Unencrypted message received: " + msg + " from "
					+ sessionID);
		}

		public void showError(SessionID sessionID, String error)
				throws OtrException {
			logger.severe("IM shows error to user: " + error);
		}

		public String getReplyForUnreadableMessage(SessionID sessionID) {
			return "You sent me an unreadable encrypted message.";
		}

		public void sessionStatusChanged(SessionID sessionID) {
			// don't care.
		}

		public KeyPair getLocalKeyPair(SessionID paramSessionID) {
			KeyPairGenerator kg;
			try {
				kg = KeyPairGenerator.getInstance("DSA");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
			return kg.genKeyPair();
		}

		public void askForSecret(SessionID sessionID, String question) {
			logger.finest("Ask for secret from: " + sessionID + ", question: "
					+ question);
		}

		public void verify(SessionID sessionID, boolean approved) {
			logger.finest("Session was verified: " + sessionID);
			if (!approved)
				logger.finest("Your answer for the question was verified."
						+ "You should ask your opponent too or check shared secret.");
		}

		public void unverify(SessionID sessionID) {
			logger.finest("Session was not verified: " + sessionID);
		}

		public byte[] getLocalFingerprintRaw(SessionID sessionID) {
			try {
				return new OtrCryptoEngineImpl()
						.getFingerprintRaw(getLocalKeyPair(sessionID)
								.getPublic());
			} catch (OtrCryptoException e) {
				e.printStackTrace();
			}
			return null;
		}

		public String getFallbackMessage(SessionID sessionID) {
			return "Off-the-Record private conversation has been requested. However, you do not have a plugin to support that.";
		}

	}

	public void testSession1() throws Exception {

		this.startSession();
		this.exchageMessages();
		this.endSession();
	}

	public void testSession2() throws Exception {

		this.startSessionWithQuery();
		this.exchageMessages();
		this.endSession();
	}

	private OtrEngineImpl usAlice;
	private OtrEngineImpl usBob;
	private DummyOtrEngineHost host;

	private void startSession() throws OtrException {
		host = new DummyOtrEngineHost(new OtrPolicyImpl(OtrPolicy.ALLOW_V2
				| OtrPolicy.ERROR_START_AKE));

		usAlice = new OtrEngineImpl(host);
		usBob = new OtrEngineImpl(host);

		usAlice.startSession(aliceSessionID);

		// Bob receives query, sends D-H commit.

		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		// Alice received D-H Commit, sends D-H key.
		usAlice
				.transformReceiving(aliceSessionID,
						host.lastInjectedMessage);

		// Bob receives D-H Key, sends reveal signature.
		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		// Alice receives Reveal Signature, sends signature and goes secure.
		usAlice
				.transformReceiving(aliceSessionID,
						host.lastInjectedMessage);

		// Bobs receives Signature, goes secure.
		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		if (usBob.getSessionStatus(bobSessionID) != SessionStatus.ENCRYPTED
				|| usAlice.getSessionStatus(aliceSessionID) != SessionStatus.ENCRYPTED)
			fail("Could not establish a secure session.");
	}

	private void startSessionWithQuery() throws OtrException {
		host = new DummyOtrEngineHost(new OtrPolicyImpl(OtrPolicy.ALLOW_V2
				| OtrPolicy.ERROR_START_AKE));

		usAlice = new OtrEngineImpl(host);
		usBob = new OtrEngineImpl(host);

		usAlice.transformReceiving(aliceSessionID, "<p>?OTRv23?\n" +
				"<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>.  However, you do not have a plugin to support that.\n" +
				"See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>");

		// Bob receives query, sends D-H commit.

		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		// Alice received D-H Commit, sends D-H key.
		usAlice
				.transformReceiving(aliceSessionID,
						host.lastInjectedMessage);

		// Bob receives D-H Key, sends reveal signature.
		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		// Alice receives Reveal Signature, sends signature and goes secure.
		usAlice
				.transformReceiving(aliceSessionID,
						host.lastInjectedMessage);

		// Bobs receives Signature, goes secure.
		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		if (usBob.getSessionStatus(bobSessionID) != SessionStatus.ENCRYPTED
				|| usAlice.getSessionStatus(aliceSessionID) != SessionStatus.ENCRYPTED)
			fail("Could not establish a secure session.");
	}

	private void exchageMessages() throws OtrException {
		// We are both secure, send encrypted message.
		String clearTextMessage = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what is that supposed to mean?";
		String sentMessage = usAlice.transformSending(aliceSessionID,
				clearTextMessage);

		// Receive encrypted message.
		String receivedMessage = usBob.transformReceiving(bobSessionID,
				sentMessage);

		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message.
		clearTextMessage = "Hey Alice, it means that our communication is encrypted and authenticated.";
		sentMessage = usBob.transformSending(bobSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				sentMessage);
		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message.
		clearTextMessage = "Oh, is that all?";
		sentMessage = usAlice
				.transformSending(aliceSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usBob.transformReceiving(bobSessionID, sentMessage);
		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message.
		clearTextMessage = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
		sentMessage = usBob.transformSending(bobSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				sentMessage);
		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message. Test UTF-8 space characters.
		clearTextMessage = "Oh really?! pouvons-nous parler en français?";
		sentMessage = usAlice
				.transformSending(aliceSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usBob.transformReceiving(bobSessionID, sentMessage);
		if (!clearTextMessage.equals(receivedMessage))
			fail();
	}

	private void endSession() throws OtrException {
		usBob.endSession(bobSessionID);
		usAlice.endSession(aliceSessionID);

		if (usBob.getSessionStatus(bobSessionID) != SessionStatus.PLAINTEXT
				|| usAlice.getSessionStatus(aliceSessionID) != SessionStatus.PLAINTEXT)
			fail("Failed to end session.");
	}
}
