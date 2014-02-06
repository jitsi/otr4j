package net.java.otr4j.session;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.crypto.OtrCryptoException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.Queue;
import java.util.logging.Logger;

/**
 * Created by gp on 2/5/14.
 */
public class DummyClient {

	private static Logger logger = Logger.getLogger(SessionImplTest.class
			.getName());
	private final String account;
	private Session session;
	private OtrPolicy policy;
	private Connection connection;
	private MessageProcessor processor;
	private Queue<ProcessedMessage> processedMsgs = new LinkedList<ProcessedMessage>();

	public DummyClient(String account) {
		this.account = account;
	}

	public Session getSession() {
		return session;
	}

	public String getAccount() {
		return account;
	}

	public void setPolicy(OtrPolicy policy) {
		this.policy = policy;
	}

	public void send(String recipient, String s) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
		}

		String outgoingMessage = session.transformSending(s);
		connection.send(recipient, outgoingMessage);
	}

	public void exit() throws OtrException {
		this.processor.stop();
		if (session != null)
			session.endSession();
	}

	public void receive(String sender, String s) throws OtrException {
		this.processor.enqueue(sender, s);
	}

	public void connect(Server server) {
		this.processor = new MessageProcessor();
		new Thread(this.processor).start();
		this.connection = server.connect(this);
	}

	public void secureSession(String recipient) throws OtrException {
		if (session == null) {
			final SessionID sessionID = new SessionID(account, recipient, "DummyProtocol");
			session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
		}

		session.startSession();
	}

	public Connection getConnection() {
		return connection;
	}

	public ProcessedMessage pollReceivedMessage() {
		synchronized (processedMsgs) {
			ProcessedMessage m;
			while ((m = processedMsgs.poll()) == null) {
				try {
					processedMsgs.wait();
				} catch (InterruptedException e) {
				}
			}

			return m;
		}
	}

	class MessageProcessor implements Runnable {
		private final Queue<Message> messageQueue = new LinkedList<Message>();
		private boolean stopped;

		private void process(Message m) throws OtrException {
			if (session == null) {
				final SessionID sessionID = new SessionID(account, m.getSender(), "DummyProtocol");
				session = new SessionImpl(sessionID, new DummyOtrEngineHostImpl());
			}

			String receivedMessage = session.transformReceiving(m.getContent());
			synchronized (processedMsgs) {
				processedMsgs.add(new ProcessedMessage(m, receivedMessage));
				processedMsgs.notify();
			}
		}

		public void run() {
			synchronized (messageQueue) {
				while (true) {

					Message m = messageQueue.poll();

					if (m == null) {
						try {
							messageQueue.wait();
						} catch (InterruptedException e) {

						}
					} else {
						try {
							process(m);
						} catch (OtrException e) {
							e.printStackTrace();
						}
					}

					if (stopped)
						break;
				}
			}
		}

		public void enqueue(String sender, String s) {
			synchronized (messageQueue) {
				messageQueue.add(new Message(sender, s));
				messageQueue.notify();
			}
		}

		public void stop() {
			stopped = true;

			synchronized (messageQueue) {
				messageQueue.notify();
			}
		}
	}

	class DummyOtrEngineHostImpl implements OtrEngineHost {

		public void injectMessage(SessionID sessionID, String msg) throws OtrException {

			connection.send(sessionID.getUserID(), msg);

			String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10)
					+ "..." : msg;
			logger.finest("IM injects message: " + msgDisplay);
		}

		public void smpError(SessionID sessionID, int tlvType, boolean cheated)
				throws OtrException {
			logger.severe("SM verification error with user: " + sessionID);
		}

		public void smpAborted(SessionID sessionID) throws OtrException {
			logger.severe("SM verification has been aborted by user: "
					+ sessionID);
		}

		public void finishedSessionMessage(SessionID sessionID, String msgText) throws OtrException {
			logger.severe("SM session was finished. You shouldn't send messages to: "
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

		public String getReplyForUnreadableMessage() {
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

		public OtrPolicy getSessionPolicy(SessionID ctx) {
			return policy;
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

		public void askForSecret(SessionID sessionID, InstanceTag receiverTag, String question) {

		}

		public void verify(SessionID sessionID, String fingerprint, boolean approved) {

		}

		public void unverify(SessionID sessionID, String fingerprint) {

		}

		public String getReplyForUnreadableMessage(SessionID sessionID) {
			return null;
		}

		public String getFallbackMessage(SessionID sessionID) {
			return null;
		}

		public void messageFromAnotherInstanceReceived(SessionID sessionID) {

		}

		public void multipleInstancesDetected(SessionID sessionID) {

		}

		public String getFallbackMessage() {
			return "Off-the-Record private conversation has been requested. However, you do not have a plugin to support that.";
		}
	}
}
