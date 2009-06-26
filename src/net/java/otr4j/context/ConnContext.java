package net.java.otr4j.context;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Vector;

import javax.crypto.interfaces.DHPublicKey;

import org.apache.log4j.Logger;

import net.java.otr4j.context.auth.AuthenticationInfo;
import net.java.otr4j.crypto.CryptoUtils;

/**
 * 
 * @author george
 */
public class ConnContext {
	public String user;
	public String account;
	public String protocol;
	public MessageState messageState;

	public AuthenticationInfo authenticationInfo;

	private static Logger logger = Logger.getLogger(ConnContext.class);

	interface SessionKeysIndex {
		public final int Previous = 0;
		public final int Current = 1;
	}

	public String lastSentMessage;

	public ConnContext(String user, String account, String protocol) {
		this.user = user;
		this.account = account;
		this.protocol = protocol;
		this.messageState = MessageState.PLAINTEXT;
		this.authenticationInfo = new AuthenticationInfo();

		for (int i = 0; i < sessionKeys.length; i++) {
			for (int j = 0; j < sessionKeys[i].length; j++) {
				int localKeyIndex = i;
				int remoteKeyIndex = j;
				sessionKeys[i][j] = new SessionKeys(localKeyIndex,
						remoteKeyIndex);
			}
		}
	}

	public SessionKeys getMostRecentSessionKeys() {
		return sessionKeys[SessionKeysIndex.Current][SessionKeysIndex.Current];
	}

	public SessionKeys[][] sessionKeys = new SessionKeys[2][2];
	
	public SessionKeys findSessionKeysByID(int localKeyID, int remoteKeyID) {
		logger
				.info("Searching for session keys with (localKeyID, remoteKeyID) = ("
						+ localKeyID + "," + remoteKeyID + ")");

		for (int i = 0; i < sessionKeys.length; i++) {
			for (int j = 0; j < sessionKeys[i].length; j++) {
				SessionKeys current = sessionKeys[i][j];
				if (current.localKeyID == localKeyID
						&& current.remoteKeyID == remoteKeyID) {
					logger.info("Matching keys found.");
					return current;
				}
			}
		}

		return null;
	}

	private Vector<byte[]> oldMacKeys = new Vector<byte[]>();

	public byte[] getOldMacKeys() {
		int len = 0;
		for (int i = 0; i < oldMacKeys.size(); i++) {
			len += oldMacKeys.get(i).length;
		}
		ByteBuffer buff = ByteBuffer.allocate(len);
		for (int i = 0; i < oldMacKeys.size(); i++) {
			buff.put(oldMacKeys.get(i));
		}
		oldMacKeys.clear();
		return buff.array();
	}

	public void rotateRemoteKeys(DHPublicKey pubKey)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException {

		logger.info("Rotating remote keys.");
		SessionKeys sess1 = sessionKeys[SessionKeysIndex.Current][SessionKeysIndex.Previous];
		if (sess1.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess1.getReceivingMACKey());
		}

		SessionKeys sess2 = sessionKeys[SessionKeysIndex.Previous][SessionKeysIndex.Previous];
		if (sess2.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess2.getReceivingMACKey());
		}

		SessionKeys sess3 = sessionKeys[SessionKeysIndex.Current][SessionKeysIndex.Current];
		sess1.setRemoteDHPublicKey(sess3.remoteKey, sess3.remoteKeyID);

		SessionKeys sess4 = sessionKeys[SessionKeysIndex.Previous][SessionKeysIndex.Current];
		sess2.setRemoteDHPublicKey(sess4.remoteKey, sess4.remoteKeyID);

		sess3.setRemoteDHPublicKey(pubKey, sess3.remoteKeyID + 1);
		sess4.setRemoteDHPublicKey(pubKey, sess4.remoteKeyID + 1);
	}

	public void rotateLocalKeys() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			IOException, InvalidKeyException {

		logger.info("Rotating local keys.");
		SessionKeys sess1 = sessionKeys[SessionKeysIndex.Previous][SessionKeysIndex.Current];
		if (sess1.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess1.getReceivingMACKey());
		}

		SessionKeys sess2 = sessionKeys[SessionKeysIndex.Previous][SessionKeysIndex.Previous];
		if (sess2.getIsUsedReceivingMACKey()) {
			logger
					.info("Detected used Receiving MAC key. Adding to old MAC keys to reveal it.");
			oldMacKeys.add(sess2.getReceivingMACKey());
		}

		SessionKeys sess3 = sessionKeys[SessionKeysIndex.Current][SessionKeysIndex.Current];
		sess1.setLocalPair(sess3.localPair, sess3.localKeyID);
		SessionKeys sess4 = sessionKeys[SessionKeysIndex.Current][SessionKeysIndex.Previous];
		sess2.setLocalPair(sess4.localPair, sess4.localKeyID);

		KeyPair newPair = CryptoUtils.generateDHKeyPair();
		sess3.setLocalPair(newPair, sess3.localKeyID + 1);
		sess4.setLocalPair(newPair, sess4.localKeyID + 1);
	}

}
