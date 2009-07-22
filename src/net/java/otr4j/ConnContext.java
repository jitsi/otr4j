/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.logging.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;

import net.java.otr4j.message.*;

/**
 * 
 * @author George Politis
 */
public class ConnContext {

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

	private String user;
	private String account;
	private String protocol;
	private OTR4jListener listener;
	private int messageState;
	private AuthContext authContext;
	private SessionKeys[][] sessionKeys;
	private Vector<byte[]> oldMacKeys;
	private static Logger logger = Logger
			.getLogger(ConnContext.class.getName());

	private static final int PLAINTEXT = 0;
	private static final int ENCRYPTED = 1;
	private static final int FINISHED = 2;

	public ConnContext(String user, String account, String protocol,
			OTR4jListener listener) {
		this.setUser(user);
		this.setAccount(account);
		this.setProtocol(protocol);
		this.setListener(listener);
		this.setMessageState(PLAINTEXT);
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
			getSessionKeys()[localKeyIndex][remoteKeyIndex] = new SessionKeys(
					localKeyIndex, remoteKeyIndex);

		return getSessionKeys()[localKeyIndex][remoteKeyIndex];
	}

	private void rotateRemoteSessionKeys(DHPublicKey pubKey)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException {

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

	private void rotateLocalSessionKeys() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			IOException, InvalidKeyException, InvalidKeySpecException {

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

		KeyPair newPair = CryptoUtils.generateDHKeyPair();
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

	private void setMessageState(int messageState) {
		this.messageState = messageState;
	}

	private int getMessageState() {
		return messageState;
	}

	private void setUser(String user) {
		this.user = user;
	}

	public String getUser() {
		return user;
	}

	private void setAccount(String account) {
		this.account = account;
	}

	public String getAccount() {
		return account;
	}

	private void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public String getProtocol() {
		return protocol;
	}

	private void setListener(OTR4jListener listener) {
		this.listener = listener;
	}

	private OTR4jListener getListener() {
		return listener;
	}

	private SessionKeys[][] getSessionKeys() {
		if (sessionKeys == null)
			sessionKeys = new SessionKeys[2][2];
		return sessionKeys;
	}

	private AuthContext getAuthContext() {
		if (authContext == null)
			authContext = new AuthContext(getAccount(), getUser(),
					getProtocol(), getListener());
		return authContext;
	}

	private Vector<byte[]> getOldMacKeys() {
		if (oldMacKeys == null)
			oldMacKeys = new Vector<byte[]>();
		return oldMacKeys;
	}

	public String handleReceivingMessage(String msgText) throws Exception {

		int policy = getListener().getPolicy(this);
		if (!PolicyUtils.getAllowV1(policy) && !PolicyUtils.getAllowV2(policy)) {
			logger
					.info("Policy does not allow neither V1 not V2, ignoring message.");
			return msgText;
		}

		switch (MessageUtils.getMessageType(msgText)) {
		case MessageConstants.DATA:
			return handleDataMessage(msgText);
		case MessageConstants.ERROR:
			handleErrorMessage(msgText, policy);
			return null;
		case MessageConstants.PLAINTEXT:
			return handlePlainTextMessage(msgText, policy);
		case MessageConstants.V1_KEY_EXCHANGE:
			throw new UnsupportedOperationException(
					"Received V1 key exchange which is not supported.");
		case MessageConstants.QUERY:
			handleQueryMessage(msgText, policy);
			return null;
		case MessageConstants.DH_COMMIT:
		case MessageConstants.DH_KEY:
		case MessageConstants.REVEALSIG:
		case MessageConstants.SIGNATURE:
			handleAuthMessage(msgText, policy);
			return null;
		default:
		case MessageConstants.UKNOWN:
			throw new UnsupportedOperationException(
					"Received an uknown message type.");
		}
	}

	private void handleQueryMessage(String msgText, int policy)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		logger.info(account + " received a query message from " + user
				+ " throught " + protocol + ".");

		QueryMessage queryMessage = new QueryMessage(msgText);
		if (queryMessage.getVersions().contains(2)
				&& PolicyUtils.getAllowV2(policy)) {
			logger.info("Query message with V2 support found.");
			getAuthContext().startV2Auth();
		} else if (queryMessage.getVersions().contains(1)
				&& PolicyUtils.getAllowV1(policy)) {
			throw new UnsupportedOperationException();
		}
	}

	private void handleErrorMessage(String msgText, int policy) {
		logger.info(account + " received an error message from " + user
				+ " throught " + protocol + ".");

		ErrorMessage errorMessage = new ErrorMessage(msgText);
		getListener().showError(errorMessage.error);
		if (PolicyUtils.getErrorStartsAKE(policy)) {
			logger.info("Error message starts AKE.");
			Vector<Integer> versions = new Vector<Integer>();
			if (PolicyUtils.getAllowV1(policy))
				versions.add(1);

			if (PolicyUtils.getAllowV2(policy))
				versions.add(2);

			QueryMessage queryMessage = new QueryMessage(versions);

			logger.info("Sending Query");
			getListener().injectMessage(queryMessage.toString(), getAccount(),
					getUser(), getProtocol());
		}
	}

	private String handleDataMessage(String msgText) throws IOException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, InvalidKeySpecException {
		logger.info(account + " received a data message from " + user + ".");
		DataMessage data = new DataMessage();
		ByteArrayInputStream in = new ByteArrayInputStream(MessageUtils
				.decodeMessage(msgText));
		data.readObject(in);
		switch (this.getMessageState()) {
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
			byte[] serializedT = t.toByteArray();
			byte[] computedMAC = CryptoUtils.sha1Hmac(serializedT, matchingKeys
					.getReceivingMACKey(), SerializationConstants.MAC);

			if (!Arrays.equals(computedMAC, data.getMac())) {
				logger.info("MAC verification failed, ignoring message");
				return null;
			}

			logger.info("Computed HmacSHA1 value matches sent one.");

			// Mark this MAC key as old to be revealed.
			matchingKeys.setIsUsedReceivingMACKey(true);

			matchingKeys.setReceivingCtr(t.ctr);

			String decryptedMsgContent = new String(CryptoUtils.aesDecrypt(
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
					int type = SerializationUtils.readShort(tin);
					byte[] tdata = SerializationUtils.readTlvData(tin);
					tlvs.add(new TLV(type, tdata));
				}
			}
			if (tlvs != null && tlvs.size() > 0) {
				for (TLV tlv : tlvs) {
					switch (tlv.getType()) {
					case 1:
						this.setMessageState(FINISHED);
						return null;
					default:
						return decryptedMsgContent;
					}
				}
			}

			return decryptedMsgContent;

		case FINISHED:
		case PLAINTEXT:
			getListener().showWarning(
					"Unreadable encrypted message was received.");
			ErrorMessage errormsg = new ErrorMessage("You sent me an unreadable encrypted message..");
			getListener().injectMessage(errormsg.toString(), getAccount(),
					getUser(), getProtocol());
			break;
		}

		return null;
	}

	private String handlePlainTextMessage(String msgText, int policy)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, IOException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, SignatureException {
		logger.info(account + " received a plaintext message from " + user
				+ " throught " + protocol + ".");

		PlainTextMessage plainTextMessage = new PlainTextMessage(msgText);
		Vector<Integer> versions = plainTextMessage.getVersions();
		if (versions.size() < 1) {
			logger
					.info("Received plaintext message without the whitespace tag.");
			switch (this.getMessageState()) {
			case ENCRYPTED:
			case FINISHED:
				// Display the message to the user, but warn him that the
				// message was received unencrypted.
				getListener().showWarning(
						"The message was received unencrypted.");
				return plainTextMessage.getCleanText();
			case PLAINTEXT:
				// Simply display the message to the user. If
				// REQUIRE_ENCRYPTION
				// is set, warn him that the message was received
				// unencrypted.
				if (PolicyUtils.getRequireEncryption(policy)) {
					getListener().showWarning(
							"The message was received unencrypted.");
				}
				return plainTextMessage.getCleanText();
			}
		} else {
			logger.info("Received plaintext message with the whitespace tag.");
			switch (this.getMessageState()) {
			case ENCRYPTED:
			case FINISHED:
				// Remove the whitespace tag and display the message to the
				// user, but warn him that the message was received
				// unencrypted.
				getListener().showWarning(
						"The message was received unencrypted.");
			case PLAINTEXT:
				// Remove the whitespace tag and display the message to the
				// user. If REQUIRE_ENCRYPTION is set, warn him that the
				// message
				// was received unencrypted.
				if (PolicyUtils.getRequireEncryption(policy))
					getListener().showWarning(
							"The message was received unencrypted.");
			}

			if (PolicyUtils.getWhiteSpaceStartsAKE(policy)) {
				logger.info("WHITESPACE_START_AKE is set");

				if (plainTextMessage.getVersions().contains(2)
						&& PolicyUtils.getAllowV2(policy)) {
					logger.info("V2 tag found.");
					getAuthContext().startV2Auth();
				} else if (plainTextMessage.getVersions().contains(1)
						&& PolicyUtils.getAllowV1(policy)) {
					throw new UnsupportedOperationException();
				}
			}
		}

		return msgText;
	}

	private void handleAuthMessage(String msgText, int policy)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, IOException, InvalidKeyException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, SignatureException {

		AuthContext auth = this.getAuthContext();
		auth.handleReceivingMessage(msgText, policy);

		if (auth.getIsSecure()) {
			logger.info("Setting most recent session keys from auth.");
			for (int i = 0; i < this.getSessionKeys()[0].length; i++) {
				SessionKeys current = getSessionKeysByIndex(0, i);
				current.setLocalPair(this.getAuthContext().getLocalDHKeyPair(),
						1);
				current.setRemoteDHPublicKey(this.getAuthContext()
						.getRemoteDHPublicKey(), 1);
				current.setS(this.getAuthContext().getS());
			}

			KeyPair nextDH = CryptoUtils.generateDHKeyPair();
			for (int i = 0; i < this.getSessionKeys()[1].length; i++) {
				SessionKeys current = getSessionKeysByIndex(1, i);
				current.setRemoteDHPublicKey(getAuthContext()
						.getRemoteDHPublicKey(), 1);
				current.setLocalPair(nextDH, 2);
			}

			auth.reset();
			this.setMessageState(ENCRYPTED);
			logger.info("Gone Secure.");
		}
	}

	public String handleSendingMessage(String msgText)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		switch (this.getMessageState()) {
		case PLAINTEXT:
			return msgText;
		case ENCRYPTED:
			logger.info(account + " sends an encrypted message to " + user
					+ " throught " + protocol + ".");

			// Get encryption keys.
			SessionKeys encryptionKeys = this.getEncryptionSessionKeys();
			int senderKeyID = encryptionKeys.getLocalKeyID();
			int receipientKeyID = encryptionKeys.getRemoteKeyID();

			// Increment CTR.
			encryptionKeys.incrementSendingCtr();
			byte[] ctr = encryptionKeys.getSendingCtr();

			// Encrypt message.
			logger
					.info("Encrypting message with keyids (localKeyID, remoteKeyID) = ("
							+ senderKeyID + ", " + receipientKeyID + ")");
			byte[] encryptedMsg = CryptoUtils.aesEncrypt(encryptionKeys
					.getSendingAESKey(), ctr, msgText.getBytes());

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
			byte[] serializedT = t.toByteArray();
			byte[] mac = CryptoUtils.sha1Hmac(serializedT, sendingMACKey,
					SerializationConstants.MAC);

			// Get old MAC keys to be revealed.
			byte[] oldMacKeys = this.collectOldMacKeys();
			DataMessage msg = new DataMessage(t, mac, oldMacKeys);
			return msg.writeObject();
		case FINISHED:
			return msgText;
		default:
			return msgText;
		}
	}

}
