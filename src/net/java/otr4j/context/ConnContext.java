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

import javax.crypto.interfaces.*;

import net.java.otr4j.context.auth.*;
import net.java.otr4j.crypto.*;

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

	public SessionKeys getEncryptionSessionKeys() {
		logger.info("Getting encryption keys");
		return getSessionKeysByIndex(SessionKeysIndex.Previous,
				SessionKeysIndex.Current);
	}

	public SessionKeys getMostRecentSessionKeys() {
		logger.info("Getting most recent keys.");
		return getSessionKeysByIndex(SessionKeysIndex.Current,
				SessionKeysIndex.Current);
	}

	public SessionKeys findSessionKeysByID(int localKeyID, int remoteKeyID) {
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

	public byte[] getOldMacKeys() {
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

	public void rotateKeys(int receipientKeyID, int senderKeyID,
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

	public void goSecure() throws NoSuchAlgorithmException,
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

	public MessageState getMessageState() {
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

	public AuthenticationInfo getAuthenticationInfo() {
		if (authenticationInfo == null)
			authenticationInfo = new AuthenticationInfo();
		return authenticationInfo;
	}
}
