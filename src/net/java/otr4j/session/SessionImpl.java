/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.session;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import java.util.logging.Logger;
import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.message.DataMessage;
import net.java.otr4j.message.ErrorMessage;
import net.java.otr4j.message.MessageConstants;
import net.java.otr4j.message.MessageUtils;
import net.java.otr4j.message.MysteriousT;
import net.java.otr4j.message.PlainTextMessage;
import net.java.otr4j.message.QueryMessage;
import net.java.otr4j.message.SerializationConstants;
import net.java.otr4j.message.SerializationUtils;

/**
 * 
 * @author George Politis
 */
public class SessionImpl implements Session {

	/**
	 * 
	 * @author George Politis
	 * 
	 */
	class TLV {
		public TLV(int type, byte[] value) {
			this.setType(type);
			this.setValue(value);
		}

		public void setType(int type) {
			this.type = type;
		}

		public int getType() {
			return type;
		}

		public void setValue(byte[] value) {
			this.value = value;
		}

		public byte[] getValue() {
			return value;
		}

		private int type;
		private byte[] value;
	}

	private SessionID sessionID;
	private OtrEngineHost listener;
	private SessionStatus sessionStatus;
	private AuthContext authContext;
	private SessionKeys[][] sessionKeys;
	private Vector<byte[]> oldMacKeys;
	private static Logger logger = Logger
			.getLogger(SessionImpl.class.getName());

	public SessionImpl(SessionID sessionID, OtrEngineHost listener) {

		this.setSessionID(sessionID);
		this.setListener(listener);

		// client application calls OtrEngine.getSessionStatus()
		// -> create new session if it does not exist, end up here
		// -> setSessionStatus() fires statusChangedEvent
		// -> client application calls OtrEngine.getSessionStatus()
		this.sessionStatus = SessionStatus.PLAINTEXT;
	}

	private SessionKeys getEncryptionSessionKeys() {
		logger.info("Getting encryption keys");
		return getSessionKeysByIndex(SessionKeys.Previous, SessionKeys.Current);
	}

	private SessionKeys getMostRecentSessionKeys() {
		logger.info("Getting most recent keys.");
		return getSessionKeysByIndex(SessionKeys.Current, SessionKeys.Current);
	}

	private SessionKeys getSessionKeysByID(int localKeyID, int remoteKeyID) {
		logger
				.info("Searching for session keys with (localKeyID, remoteKeyID) = ("
						+ localKeyID + "," + remoteKeyID + ")");

		for (int i = 0; i < getSessionKeys().length; i++) {
			for (int j = 0; j < getSessionKeys()[i].length; j++) {
				SessionKeys current = getSessionKeysByIndex(i, j);
				if (current.getLocalKeyID() == localKeyID
						&& current.getRemoteKeyID() == remoteKeyID) {
					logger.info("Matching keys found.");
					return current;
				}
			}
		}

		return null;
	}

	private SessionKeys getSessionKeysByIndex(int localKeyIndex,
			int remoteKeyIndex) {
		if (getSessionKeys()[localKeyIndex][remoteKeyIndex] == null)
			getSessionKeys()[localKeyIndex][remoteKeyIndex] = new SessionKeysImpl(
					localKeyIndex, remoteKeyIndex);

		return getSessionKeys()[localKeyIndex][remoteKeyIndex];
	}

	private void rotateRemoteSessionKeys(DHPublicKey pubKey)
			throws OtrException {

		logger.info("Rotating remote keys.");
		SessionKeys sess1 = getSessionKeysByIndex(SessionKeys.Current,
				SessionKeys.Previous);
		if (sess1.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			getOldMacKeys().add(sess1.getReceivingMACKey());
		}

		SessionKeys sess2 = getSessionKeysByIndex(SessionKeys.Previous,
				SessionKeys.Previous);
		if (sess2.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			getOldMacKeys().add(sess2.getReceivingMACKey());
		}

		SessionKeys sess3 = getSessionKeysByIndex(SessionKeys.Current,
				SessionKeys.Current);
		sess1
				.setRemoteDHPublicKey(sess3.getRemoteKey(), sess3
						.getRemoteKeyID());

		SessionKeys sess4 = getSessionKeysByIndex(SessionKeys.Previous,
				SessionKeys.Current);
		sess2
				.setRemoteDHPublicKey(sess4.getRemoteKey(), sess4
						.getRemoteKeyID());

		sess3.setRemoteDHPublicKey(pubKey, sess3.getRemoteKeyID() + 1);
		sess4.setRemoteDHPublicKey(pubKey, sess4.getRemoteKeyID() + 1);
	}

	private void rotateLocalSessionKeys() throws OtrException {

		logger.info("Rotating local keys.");
		SessionKeys sess1 = getSessionKeysByIndex(SessionKeys.Previous,
				SessionKeys.Current);
		if (sess1.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			getOldMacKeys().add(sess1.getReceivingMACKey());
		}

		SessionKeys sess2 = getSessionKeysByIndex(SessionKeys.Previous,
				SessionKeys.Previous);
		if (sess2.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			getOldMacKeys().add(sess2.getReceivingMACKey());
		}

		SessionKeys sess3 = getSessionKeysByIndex(SessionKeys.Current,
				SessionKeys.Current);
		sess1.setLocalPair(sess3.getLocalPair(), sess3.getLocalKeyID());
		SessionKeys sess4 = getSessionKeysByIndex(SessionKeys.Current,
				SessionKeys.Previous);
		sess2.setLocalPair(sess4.getLocalPair(), sess4.getLocalKeyID());

		KeyPair newPair = new OtrCryptoEngineImpl().generateDHKeyPair();
		sess3.setLocalPair(newPair, sess3.getLocalKeyID() + 1);
		sess4.setLocalPair(newPair, sess4.getLocalKeyID() + 1);
	}

	private byte[] collectOldMacKeys() {
		logger.info("Collecting old MAC keys to be revealed.");
		int len = 0;
		for (int i = 0; i < getOldMacKeys().size(); i++)
			len += getOldMacKeys().get(i).length;

		ByteBuffer buff = ByteBuffer.allocate(len);
		for (int i = 0; i < getOldMacKeys().size(); i++)
			buff.put(getOldMacKeys().get(i));

		getOldMacKeys().clear();
		return buff.array();
	}

	private void setSessionStatus(SessionStatus sessionStatus)
			throws OtrException {

		if (sessionStatus == this.sessionStatus)
			return;

		switch (sessionStatus) {
		case ENCRYPTED:
			AuthContext auth = this.getAuthContext();
			logger.info("Setting most recent session keys from auth.");
			for (int i = 0; i < this.getSessionKeys()[0].length; i++) {
				SessionKeys current = getSessionKeysByIndex(0, i);
				current.setLocalPair(auth.getLocalDHKeyPair(), 1);
				current.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
				current.setS(auth.getS());
			}

			KeyPair nextDH = new OtrCryptoEngineImpl().generateDHKeyPair();
			for (int i = 0; i < this.getSessionKeys()[1].length; i++) {
				SessionKeys current = getSessionKeysByIndex(1, i);
				current.setRemoteDHPublicKey(auth.getRemoteDHPublicKey(), 1);
				current.setLocalPair(nextDH, 2);
			}

			this.setRemotePublicKey(auth.getRemoteLongTermPublicKey());

			auth.reset();
			break;
		}

		this.sessionStatus = sessionStatus;
		getListener().sessionStatusChanged(getSessionID());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.java.otr4j.session.ISession#getSessionStatus()
	 */

	public SessionStatus getSessionStatus() {
		return sessionStatus;
	}

	private void setSessionID(SessionID sessionID) {
		this.sessionID = sessionID;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.java.otr4j.session.ISession#getSessionID()
	 */
	public SessionID getSessionID() {
		return sessionID;
	}

	private void setListener(OtrEngineHost listener) {
		this.listener = listener;
	}

	private OtrEngineHost getListener() {
		return listener;
	}

	private SessionKeys[][] getSessionKeys() {
		if (sessionKeys == null)
			sessionKeys = new SessionKeys[2][2];
		return sessionKeys;
	}

	private AuthContext getAuthContext() {
		if (authContext == null)
			authContext = new AuthContextImpl(getSessionID(), getListener());
		return authContext;
	}

	private Vector<byte[]> getOldMacKeys() {
		if (oldMacKeys == null)
			oldMacKeys = new Vector<byte[]>();
		return oldMacKeys;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * net.java.otr4j.session.ISession#handleReceivingMessage(java.lang.String)
	 */
	public String transformReceiving(String msgText) throws OtrException {
		OtrPolicy policy = getListener().getSessionPolicy(getSessionID());
		if (!policy.getAllowV1() && !policy.getAllowV2()) {
			logger
					.info("Policy does not allow neither V1 not V2, ignoring message.");
			return msgText;
		}

		switch (MessageUtils.getMessageType(msgText)) {
		case MessageConstants.DATA:
			return handleDataMessage(msgText);
		case MessageConstants.ERROR:
			handleErrorMessage(msgText);
			return null;
		case MessageConstants.PLAINTEXT:
			return handlePlainTextMessage(msgText);
		case MessageConstants.V1_KEY_EXCHANGE:
			throw new UnsupportedOperationException(
					"Received V1 key exchange which is not supported.");
		case MessageConstants.QUERY:
			handleQueryMessage(msgText);
			return null;
		case MessageConstants.DH_COMMIT:
		case MessageConstants.DH_KEY:
		case MessageConstants.REVEALSIG:
		case MessageConstants.SIGNATURE:
			handleAuthMessage(msgText);
			return null;
		default:
		case MessageConstants.UKNOWN:
			throw new UnsupportedOperationException(
					"Received an uknown message type.");
		}
	}

	private void handleQueryMessage(String msgText) throws OtrException {
		logger.info(getSessionID().getAccountID()
				+ " received a query message from "
				+ getSessionID().getUserID() + " throught "
				+ getSessionID().getProtocolName() + ".");

		QueryMessage queryMessage = new QueryMessage(msgText);
		if (queryMessage.getVersions().contains(2)
				&& this.getListener().getSessionPolicy(getSessionID())
						.getAllowV2()) {
			logger.info("Query message with V2 support found.");
			getAuthContext().startV2Auth();
		} else if (queryMessage.getVersions().contains(1)
				&& this.getListener().getSessionPolicy(getSessionID())
						.getAllowV1()) {
			throw new UnsupportedOperationException();
		}
	}

	private void handleErrorMessage(String msgText) {
		logger.info(getSessionID().getAccountID()
				+ " received an error message from "
				+ getSessionID().getUserID() + " throught "
				+ getSessionID().getUserID() + ".");

		ErrorMessage errorMessage = new ErrorMessage(msgText);
		getListener().showError(this.getSessionID(), errorMessage.error);

		OtrPolicy policy = this.getListener().getSessionPolicy(getSessionID());
		if (policy.getErrorStartAKE()) {
			logger.info("Error message starts AKE.");
			Vector<Integer> versions = new Vector<Integer>();
			if (policy.getAllowV1())
				versions.add(1);

			if (policy.getAllowV2())
				versions.add(2);

			QueryMessage queryMessage = new QueryMessage(versions);

			logger.info("Sending Query");
			getListener()
					.injectMessage(getSessionID(), queryMessage.toString());
		}
	}

	private String handleDataMessage(String msgText) throws OtrException {
		logger.info(getSessionID().getAccountID()
				+ " received a data message from " + getSessionID().getUserID()
				+ ".");
		DataMessage data = new DataMessage();
		ByteArrayInputStream in = new ByteArrayInputStream(MessageUtils
				.decodeMessage(msgText));
		try {
			data.readObject(in);
		} catch (IOException e) {
			throw new OtrException(e);
		}
		switch (this.getSessionStatus()) {
		case ENCRYPTED:
			logger
					.info("Message state is ENCRYPTED. Trying to decrypt message.");
			MysteriousT t = data.getT();

			// Find matching session keys.
			int senderKeyID = t.senderKeyID;
			int receipientKeyID = t.recipientKeyID;
			SessionKeys matchingKeys = this.getSessionKeysByID(receipientKeyID,
					senderKeyID);

			if (matchingKeys == null) {
				logger.info("No matching keys found.");
				return null;
			}

			// Verify received MAC with a locally calculated MAC.
			logger.info("Transforming T to byte[] to calculate it's HmacSHA1.");
			byte[] serializedT;
			try {
				serializedT = t.toByteArray();
			} catch (IOException e) {
				throw new OtrException(e);
			}

			OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();

			byte[] computedMAC = otrCryptoEngine.sha1Hmac(serializedT,
					matchingKeys.getReceivingMACKey(),
					SerializationConstants.MAC);

			if (!Arrays.equals(computedMAC, data.getMac())) {
				logger.info("MAC verification failed, ignoring message");
				return null;
			}

			logger.info("Computed HmacSHA1 value matches sent one.");

			// Mark this MAC key as old to be revealed.
			matchingKeys.setIsUsedReceivingMACKey(true);

			matchingKeys.setReceivingCtr(t.ctr);

			String decryptedMsgContent = new String(otrCryptoEngine.aesDecrypt(
					matchingKeys.getReceivingAESKey(), matchingKeys
							.getReceivingCtr(), t.encryptedMsg));

			logger.info("Decrypted message: \"" + decryptedMsgContent + "\"");

			// Rotate keys if necessary.
			SessionKeys mostRecent = this.getMostRecentSessionKeys();
			if (mostRecent.getLocalKeyID() == receipientKeyID)
				this.rotateLocalSessionKeys();

			if (mostRecent.getRemoteKeyID() == senderKeyID)
				this.rotateRemoteSessionKeys(t.nextDHPublicKey);

			// Handle TLVs
			List<TLV> tlvs = null;
			int tlvIndex = decryptedMsgContent.indexOf((char) 0x0);
			if (tlvIndex > -1) {
				byte[] mb = decryptedMsgContent.getBytes();
				decryptedMsgContent = decryptedMsgContent
						.substring(0, tlvIndex);
				tlvIndex++;
				byte[] tlvsb = new byte[mb.length - tlvIndex];
				System.arraycopy(mb, tlvIndex, tlvsb, 0, tlvsb.length);

				tlvs = new Vector<TLV>();
				ByteArrayInputStream tin = new ByteArrayInputStream(tlvsb);
				while (tin.available() > 0) {
					int type;
					byte[] tdata;

					try {
						type = SerializationUtils.readShort(tin);
						tdata = SerializationUtils.readTlvData(tin);
					} catch (IOException e) {
						throw new OtrException(e);
					}
					tlvs.add(new TLV(type, tdata));
				}
			}
			if (tlvs != null && tlvs.size() > 0) {
				for (TLV tlv : tlvs) {
					switch (tlv.getType()) {
					case 1:
						this.setSessionStatus(SessionStatus.FINISHED);
						return null;
					default:
						return decryptedMsgContent;
					}
				}
			}

			return decryptedMsgContent;

		case FINISHED:
		case PLAINTEXT:
			getListener().showWarning(this.getSessionID(),
					"Unreadable encrypted message was received.");
			ErrorMessage errormsg = new ErrorMessage(
					"You sent me an unreadable encrypted message..");
			getListener().injectMessage(getSessionID(), errormsg.toString());
			break;
		}

		return null;
	}

	private String handlePlainTextMessage(String msgText) throws OtrException {
		logger.info(getSessionID().getAccountID()
				+ " received a plaintext message from "
				+ getSessionID().getUserID() + " throught "
				+ getSessionID().getProtocolName() + ".");

		PlainTextMessage plainTextMessage = new PlainTextMessage(msgText);
		OtrPolicy policy = getListener().getSessionPolicy(getSessionID());
		Vector<Integer> versions = plainTextMessage.getVersions();
		if (versions.size() < 1) {
			logger
					.info("Received plaintext message without the whitespace tag.");
			switch (this.getSessionStatus()) {
			case ENCRYPTED:
			case FINISHED:
				// Display the message to the user, but warn him that the
				// message was received unencrypted.
				getListener().showWarning(this.getSessionID(),
						"The message was received unencrypted.");
				return plainTextMessage.getCleanText();
			case PLAINTEXT:
				// Simply display the message to the user. If
				// REQUIRE_ENCRYPTION
				// is set, warn him that the message was received
				// unencrypted.
				if (policy.getRequireEncryption()) {
					getListener().showWarning(this.getSessionID(),
							"The message was received unencrypted.");
				}
				return plainTextMessage.getCleanText();
			}
		} else {
			logger.info("Received plaintext message with the whitespace tag.");
			switch (this.getSessionStatus()) {
			case ENCRYPTED:
			case FINISHED:
				// Remove the whitespace tag and display the message to the
				// user, but warn him that the message was received
				// unencrypted.
				getListener().showWarning(this.getSessionID(),
						"The message was received unencrypted.");
			case PLAINTEXT:
				// Remove the whitespace tag and display the message to the
				// user. If REQUIRE_ENCRYPTION is set, warn him that the
				// message
				// was received unencrypted.
				if (policy.getRequireEncryption())
					getListener().showWarning(this.getSessionID(),
							"The message was received unencrypted.");
			}

			if (policy.getWhitespaceStartAKE()) {
				logger.info("WHITESPACE_START_AKE is set");

				if (plainTextMessage.getVersions().contains(2)
						&& policy.getAllowV2()) {
					logger.info("V2 tag found.");
					getAuthContext().startV2Auth();
				} else if (plainTextMessage.getVersions().contains(1)
						&& policy.getAllowV1()) {
					throw new UnsupportedOperationException();
				}
			}
		}

		return msgText;
	}

	private void handleAuthMessage(String msgText) throws OtrException {

		AuthContext auth = this.getAuthContext();
		auth.handleReceivingMessage(msgText);

		if (auth.getIsSecure()) {
			this.setSessionStatus(SessionStatus.ENCRYPTED);
			logger.info("Gone Secure.");
		}
	}

	// Retransmit last sent message. Spec document does not mention where or
	// when that should happen, must check libotr code.
	private String lastSentMessage;

	public String transformSending(String msgText, List<TLV> tlvs)
			throws OtrException {

		switch (this.getSessionStatus()) {
		case PLAINTEXT:
			if (this.getListener().getSessionPolicy(getSessionID())
					.getRequireEncryption()) {
				this.lastSentMessage = msgText;
				this.startSession();
			} else
				// TODO this does not precisly behave according to
				// specification.
				return msgText;
		case ENCRYPTED:
			this.lastSentMessage = msgText;
			logger.info(getSessionID().getAccountID()
					+ " sends an encrypted message to "
					+ getSessionID().getUserID() + " throught "
					+ getSessionID().getProtocolName() + ".");

			// Get encryption keys.
			SessionKeys encryptionKeys = this.getEncryptionSessionKeys();
			int senderKeyID = encryptionKeys.getLocalKeyID();
			int receipientKeyID = encryptionKeys.getRemoteKeyID();

			// Increment CTR.
			encryptionKeys.incrementSendingCtr();
			byte[] ctr = encryptionKeys.getSendingCtr();

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			if (msgText != null && msgText.length() > 0)
				try {
					out.write(msgText.getBytes());
				} catch (IOException e) {
					throw new OtrException(e);
				}

			// Append tlvs
			if (tlvs != null && tlvs.size() > 0) {
				out.write((byte) 0x00);

				for (TLV tlv : tlvs) {
					try {
						SerializationUtils.writeShort(out, tlv.type);
						SerializationUtils.writeTlvData(out, tlv.value);
					} catch (IOException e) {
						throw new OtrException(e);
					}
				}
			}

			OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();

			byte[] data = out.toByteArray();
			// Encrypt message.
			logger
					.info("Encrypting message with keyids (localKeyID, remoteKeyID) = ("
							+ senderKeyID + ", " + receipientKeyID + ")");
			byte[] encryptedMsg = otrCryptoEngine.aesEncrypt(encryptionKeys
					.getSendingAESKey(), ctr, data);

			// Get most recent keys to get the next D-H public key.
			SessionKeys mostRecentKeys = this.getMostRecentSessionKeys();
			DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.getLocalPair()
					.getPublic();

			// Calculate T.
			MysteriousT t = new MysteriousT(senderKeyID, receipientKeyID,
					nextDH, ctr, encryptedMsg, 2, 0);

			// Calculate T hash.
			byte[] sendingMACKey = encryptionKeys.getSendingMACKey();

			logger.info("Transforming T to byte[] to calculate it's HmacSHA1.");
			byte[] serializedT;
			try {
				serializedT = t.toByteArray();
			} catch (IOException e) {
				throw new OtrException(e);
			}
			byte[] mac = otrCryptoEngine.sha1Hmac(serializedT, sendingMACKey,
					SerializationConstants.MAC);

			// Get old MAC keys to be revealed.
			byte[] oldMacKeys = this.collectOldMacKeys();
			DataMessage msg = new DataMessage(t, mac, oldMacKeys);
			try {
				return msg.writeObject();
			} catch (IOException e) {
				throw new OtrException(e);
			}
		case FINISHED:
			this.lastSentMessage = msgText;
			getListener()
					.showError(
							sessionID,
							"Your message to "
									+ sessionID.getUserID()
									+ " was not sent.  Either end your private conversation, or restart it.");
			return null;
		default:
			logger.info("Uknown message state, not processing.");
			return msgText;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.java.otr4j.session.ISession#startSession()
	 */
	public void startSession() throws OtrException {
		if (this.getSessionStatus() == SessionStatus.ENCRYPTED)
			return;

		if (!getListener().getSessionPolicy(getSessionID()).getAllowV2())
			throw new UnsupportedOperationException();

		this.getAuthContext().startV2Auth();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.java.otr4j.session.ISession#endSession()
	 */
	public void endSession() throws OtrException {
		SessionStatus status = this.getSessionStatus();
		switch (status) {
		case ENCRYPTED:
			Vector<TLV> tlvs = new Vector<TLV>();
			tlvs.add(new TLV(1, null));

			String msg = this.transformSending(null, tlvs);
			getListener().injectMessage(getSessionID(), msg);
			this.setSessionStatus(SessionStatus.PLAINTEXT);
			break;
		case FINISHED:
			this.setSessionStatus(SessionStatus.PLAINTEXT);
			break;
		case PLAINTEXT:
			return;
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see net.java.otr4j.session.ISession#refreshSession()
	 */
	public void refreshSession() throws OtrException {
		this.endSession();
		this.startSession();
	}

	private PublicKey remotePublicKey;

	private void setRemotePublicKey(PublicKey pubKey) {
		this.remotePublicKey = pubKey;
	}

	public PublicKey getRemotePublicKey() {
		return remotePublicKey;
	}
}
