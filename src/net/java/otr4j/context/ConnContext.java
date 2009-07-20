/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.context;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.logging.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.*;

import net.java.otr4j.OTR4jListener;
import net.java.otr4j.OtrException;
import net.java.otr4j.PolicyUtils;
import net.java.otr4j.context.auth.*;
import net.java.otr4j.crypto.*;
import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.DataMessage;
import net.java.otr4j.message.encoded.EncodedMessageUtils;
import net.java.otr4j.message.encoded.MysteriousT;
import net.java.otr4j.message.unencoded.ErrorMessage;
import net.java.otr4j.message.unencoded.query.PlainTextMessage;
import net.java.otr4j.message.unencoded.query.QueryMessage;

/**
 * 
 * @author George Politis
 */
public class ConnContext {
	private String user;
	private String account;
	private String protocol;
	private MessageState messageState;
	private AuthenticationInfo authenticationInfo;
	private SessionKeys[][] sessionKeys = new SessionKeys[2][2];
	private Vector<byte[]> oldMacKeys = new Vector<byte[]>();
	private static Logger logger = Logger
			.getLogger(ConnContext.class.getName());

	interface SessionKeysIndex {
		public final int Previous = 0;
		public final int Current = 1;
	}

	public ConnContext(String user, String account, String protocol) {
		this.setUser(user);
		this.setAccount(account);
		this.setProtocol(protocol);
		this.setMessageState(MessageState.PLAINTEXT);
	}

	private SessionKeys getEncryptionSessionKeys() {
		logger.info("Getting encryption keys");
		return getSessionKeysByIndex(SessionKeysIndex.Previous,
				SessionKeysIndex.Current);
	}

	private SessionKeys getMostRecentSessionKeys() {
		logger.info("Getting most recent keys.");
		return getSessionKeysByIndex(SessionKeysIndex.Current,
				SessionKeysIndex.Current);
	}

	private SessionKeys findSessionKeysByID(int localKeyID, int remoteKeyID) {
		logger
				.info("Searching for session keys with (localKeyID, remoteKeyID) = ("
						+ localKeyID + "," + remoteKeyID + ")");

		for (int i = 0; i < sessionKeys.length; i++) {
			for (int j = 0; j < sessionKeys[i].length; j++) {
				SessionKeys current = getSessionKeysByIndex(i, j);
				if (current.localKeyID == localKeyID
						&& current.remoteKeyID == remoteKeyID) {
					logger.info("Matching keys found.");
					return current;
				}
			}
		}

		return null;
	}

	private SessionKeys getSessionKeysByIndex(int localKeyIndex,
			int remoteKeyIndex) {
		if (sessionKeys[localKeyIndex][remoteKeyIndex] == null)
			sessionKeys[localKeyIndex][remoteKeyIndex] = new SessionKeys(
					localKeyIndex, remoteKeyIndex);

		return sessionKeys[localKeyIndex][remoteKeyIndex];
	}

	private byte[] getOldMacKeys() {
		logger.info("Collecting old MAC keys to be revealed.");
		int len = 0;
		for (int i = 0; i < oldMacKeys.size(); i++)
			len += oldMacKeys.get(i).length;

		ByteBuffer buff = ByteBuffer.allocate(len);
		for (int i = 0; i < oldMacKeys.size(); i++)
			buff.put(oldMacKeys.get(i));

		oldMacKeys.clear();
		return buff.array();
	}

	private void rotateKeys(int receipientKeyID, int senderKeyID,
			DHPublicKey pubKey) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException, IOException {
		SessionKeys mostRecent = this.getMostRecentSessionKeys();
		if (mostRecent.localKeyID == receipientKeyID)
			this.rotateLocalKeys();

		if (mostRecent.remoteKeyID == senderKeyID)
			this.rotateRemoteKeys(pubKey);
	}

	private void rotateRemoteKeys(DHPublicKey pubKey)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException {

		logger.info("Rotating remote keys.");
		SessionKeys sess1 = getSessionKeysByIndex(SessionKeysIndex.Current,
				SessionKeysIndex.Previous);
		if (sess1.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess1.getReceivingMACKey());
		}

		SessionKeys sess2 = getSessionKeysByIndex(SessionKeysIndex.Previous,
				SessionKeysIndex.Previous);
		if (sess2.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess2.getReceivingMACKey());
		}

		SessionKeys sess3 = getSessionKeysByIndex(SessionKeysIndex.Current,
				SessionKeysIndex.Current);
		sess1.setRemoteDHPublicKey(sess3.remoteKey, sess3.remoteKeyID);

		SessionKeys sess4 = getSessionKeysByIndex(SessionKeysIndex.Previous,
				SessionKeysIndex.Current);
		sess2.setRemoteDHPublicKey(sess4.remoteKey, sess4.remoteKeyID);

		sess3.setRemoteDHPublicKey(pubKey, sess3.remoteKeyID + 1);
		sess4.setRemoteDHPublicKey(pubKey, sess4.remoteKeyID + 1);
	}

	private void rotateLocalKeys() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			IOException, InvalidKeyException, InvalidKeySpecException {

		logger.info("Rotating local keys.");
		SessionKeys sess1 = getSessionKeysByIndex(SessionKeysIndex.Previous,
				SessionKeysIndex.Current);
		if (sess1.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess1.getReceivingMACKey());
		}

		SessionKeys sess2 = getSessionKeysByIndex(SessionKeysIndex.Previous,
				SessionKeysIndex.Previous);
		if (sess2.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess2.getReceivingMACKey());
		}

		SessionKeys sess3 = getSessionKeysByIndex(SessionKeysIndex.Current,
				SessionKeysIndex.Current);
		sess1.setLocalPair(sess3.localPair, sess3.localKeyID);
		SessionKeys sess4 = getSessionKeysByIndex(SessionKeysIndex.Current,
				SessionKeysIndex.Previous);
		sess2.setLocalPair(sess4.localPair, sess4.localKeyID);

		KeyPair newPair = CryptoUtils.generateDHKeyPair();
		sess3.setLocalPair(newPair, sess3.localKeyID + 1);
		sess4.setLocalPair(newPair, sess4.localKeyID + 1);
	}

	private void goSecure() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, InvalidKeyException {
		logger.info("Setting most recent session keys from auth.");
		for (int i = 0; i < this.sessionKeys[0].length; i++) {
			SessionKeys current = getSessionKeysByIndex(0, i);
			current.setLocalPair(this.getAuthenticationInfo()
					.getLocalDHKeyPair(), 1);
			current.setRemoteDHPublicKey(this.getAuthenticationInfo()
					.getRemoteDHPublicKey(), 1);
			current.setS(this.getAuthenticationInfo().getS());
		}

		KeyPair nextDH = CryptoUtils.generateDHKeyPair();
		for (int i = 0; i < this.sessionKeys[1].length; i++) {
			SessionKeys current = getSessionKeysByIndex(1, i);
			current.setRemoteDHPublicKey(getAuthenticationInfo()
					.getRemoteDHPublicKey(), 1);
			current.setLocalPair(nextDH, 2);
		}

		this.getAuthenticationInfo().reset();
		this.setMessageState(MessageState.ENCRYPTED);
		logger.info("Gone Secure.");
	}

	private void setMessageState(MessageState messageState) {
		this.messageState = messageState;
	}

	private MessageState getMessageState() {
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

	private AuthenticationInfo getAuthenticationInfo() {
		if (authenticationInfo == null)
			authenticationInfo = new AuthenticationInfo(getAccount(),
					getUser(), getProtocol());
		return authenticationInfo;
	}

	public String handleReceivingMessage(String msgText, OTR4jListener listener)
			throws Exception {
		int policy = listener.getPolicy(this);

		Boolean allowV1 = PolicyUtils.getAllowV1(policy);
		Boolean allowV2 = PolicyUtils.getAllowV2(policy);
		if (!allowV1 && !allowV2) {
			logger
					.info("Policy does not allow neither V1 not V2, ignoring message.");
			return msgText;
		}

		switch (MessageHeader.getMessageType(msgText)) {
		case MessageType.DATA:
			logger
					.info(account + " received a data message from " + user
							+ ".");
			DataMessage data = new DataMessage();
			ByteArrayInputStream in = new ByteArrayInputStream(
					EncodedMessageUtils.decodeMessage(msgText));
			data.readObject(in);
			switch (this.getMessageState()) {
			case ENCRYPTED:
				logger
						.info("Message state is ENCRYPTED. Trying to decrypt message.");
				MysteriousT t = data.t;

				// Find matching session keys.
				int senderKeyID = t.senderKeyID;
				int receipientKeyID = t.recipientKeyID;
				SessionKeys matchingKeys = this.findSessionKeysByID(
						receipientKeyID, senderKeyID);

				if (matchingKeys == null)
					throw new OtrException("No matching keys found.");

				// Verify received MAC with a locally calculated MAC.
				if (!data.verify(matchingKeys.getReceivingMACKey()))
					throw new OtrException("MAC verification failed.");

				logger.info("Computed HmacSHA1 value matches sent one.");

				// Mark this MAC key as old to be revealed.
				matchingKeys.setIsUsedReceivingMACKey(true);

				matchingKeys.setReceivingCtr(t.ctr);

				String decryptedMsgContent = t.getDecryptedMessage(matchingKeys
						.getReceivingAESKey(), matchingKeys.getReceivingCtr());
				logger.info("Decrypted message: \"" + decryptedMsgContent
						+ "\"");

				// Rotate keys if necessary.
				this
						.rotateKeys(receipientKeyID, senderKeyID,
								t.nextDHPublicKey);

				return decryptedMsgContent;
			case FINISHED:
			case PLAINTEXT:
				listener
						.showWarning("Unreadable encrypted message was received");
				ErrorMessage errormsg = new ErrorMessage("Oups.");
				listener.injectMessage(errormsg.toString());
				break;
			}

			return null;
		case MessageType.ERROR:
			logger.info(account + " received an error message from " + user
					+ " throught " + protocol + ".");

			ErrorMessage errorMessage = new ErrorMessage(msgText);
			listener.showError(errorMessage.error);
			if (PolicyUtils.getErrorStartsAKE(policy)) {
				logger.info("Error message starts AKE.");
				Vector<Integer> versions = new Vector<Integer>();
				if (PolicyUtils.getAllowV1(policy))
					versions.add(1);

				if (PolicyUtils.getAllowV2(policy))
					versions.add(2);

				QueryMessage queryMessage = new QueryMessage(versions);

				logger.info("Sending Query");
				listener.injectMessage(queryMessage.toString());
			}
			break;
		case MessageType.PLAINTEXT:
			logger.info(account + " received a plaintext message from " + user
					+ " throught " + protocol + ".");

			PlainTextMessage plainTextMessage = new PlainTextMessage(msgText);
			Vector<Integer> versions = plainTextMessage.versions;
			if (versions.size() < 1) {
				logger
						.info("Received plaintext message without the whitespace tag.");
				switch (this.getMessageState()) {
				case ENCRYPTED:
				case FINISHED:
					// Display the message to the user, but warn him that the
					// message was received unencrypted.
					listener
							.showWarning("The message was received unencrypted.");
					return plainTextMessage.cleanText;
				case PLAINTEXT:
					// Simply display the message to the user. If
					// REQUIRE_ENCRYPTION
					// is set, warn him that the message was received
					// unencrypted.
					if (PolicyUtils.getRequireEncryption(policy)) {
						listener
								.showWarning("The message was received unencrypted.");
					}
					break;
				}
			} else {
				logger
						.info("Received plaintext message with the whitespace tag.");
				String cleanText = plainTextMessage.cleanText;
				switch (this.getMessageState()) {
				case ENCRYPTED:
				case FINISHED:
					// Remove the whitespace tag and display the message to the
					// user, but warn him that the message was received
					// unencrypted.
					listener
							.showWarning("The message was received unencrypted.");
					return cleanText;
				case PLAINTEXT:
					// Remove the whitespace tag and display the message to the
					// user. If REQUIRE_ENCRYPTION is set, warn him that the
					// message
					// was received unencrypted.
					if (PolicyUtils.getRequireEncryption(policy)) {
						listener
								.showWarning("The message was received unencrypted.");
					}
					return cleanText;
				}

				if (PolicyUtils.getWhiteSpaceStartsAKE(policy)) {
					logger.info("WHITESPACE_START_AKE is set");

					if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
						logger.info("V2 tag found, starting v2 AKE.");
						AuthenticationInfo auth = this.getAuthenticationInfo();
						auth.reset();
						auth.setAuthAwaitingDHKey();

						logger.info("Sending D-H Commit.");
						listener.injectMessage(auth.getDHCommitMessage()
								.toUnsafeString());
					} else if (versions.contains(1)
							&& PolicyUtils.getAllowV1(policy)) {
						throw new UnsupportedOperationException();
					}
				}
			}
			break;
		case MessageType.QUERY:
			logger.info(account + " received a query message from " + user
					+ " throught " + protocol + ".");

			QueryMessage queryMessage = new QueryMessage(msgText);
			if (queryMessage.versions.contains(2)
					&& PolicyUtils.getAllowV2(policy)) {
				logger
						.info("Query message with V2 support found, starting V2 AKE.");
				AuthenticationInfo auth = this.getAuthenticationInfo();
				auth.reset();

				auth.setAuthAwaitingDHKey();

				logger.info("Sending D-H Commit.");
				listener.injectMessage(auth.getDHCommitMessage()
						.toUnsafeString());
			} else if (queryMessage.versions.contains(1)
					&& PolicyUtils.getAllowV1(policy)) {
				throw new UnsupportedOperationException();
			}
			logger.info("User needs to know nothing about Query messages.");
			return null;
		case MessageType.V1_KEY_EXCHANGE:
			logger.warning("Received V1 key exchange which is not supported.");
			throw new UnsupportedOperationException();
		case MessageType.UKNOWN:
			logger.warning("Unrecognizable OTR message received.");
			break;
		default:
			this.getAuthenticationInfo().handleReceivingMessage(msgText,
					listener, policy);

			if (this.getAuthenticationInfo().isSecure)
				this.goSecure();
			return null;
		}

		return null;
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
			int senderKeyID = encryptionKeys.localKeyID;
			int receipientKeyID = encryptionKeys.remoteKeyID;

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
			DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.localPair
					.getPublic();

			// Calculate T.
			MysteriousT t = new MysteriousT(senderKeyID, receipientKeyID,
					nextDH, ctr, encryptedMsg, 2, 0);

			// Calculate T hash.
			byte[] sendingMACKey = encryptionKeys.getSendingMACKey();
			byte[] mac = t.hash(sendingMACKey);

			// Get old MAC keys to be revealed.
			byte[] oldMacKeys = this.getOldMacKeys();
			DataMessage msg = new DataMessage(t, mac, oldMacKeys);
			return msg.toUnsafeString();
		case FINISHED:
			return msgText;
		default:
			return msgText;
		}
	}
}
