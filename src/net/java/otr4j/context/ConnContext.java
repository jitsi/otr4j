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

	/*
	 * sesskeys[i][j] are the session keys derived from DH key[our_keyid-i] and
	 * mpi Y[their_keyid-j]
	 */
	interface KeyIndex {
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
				sessionKeys[i][j] = new SessionKeys();
			}
		}
	}

	public SessionKeys getTopSessionKeys() {
		return sessionKeys[KeyIndex.Current][KeyIndex.Current];
	}

	public SessionKeys[][] sessionKeys = new SessionKeys[2][2];

	public SessionKeys findSessionKeys(int localKeyID, int remoteKeyID) {
		for (int i = 0; i < sessionKeys.length; i++) {
			for (int j = 0; j < sessionKeys[i].length; j++) {
				SessionKeys current = sessionKeys[i][j];
				if (current.localKeyID == localKeyID
						&& current.remoteKeyID == remoteKeyID)
					return current;
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

		SessionKeys sess1 = sessionKeys[KeyIndex.Current][KeyIndex.Previous];
		if (sess1.isUsedReceivingMACKey)
			oldMacKeys.add(sess1.getReceivingMACKey());

		SessionKeys sess2 = sessionKeys[KeyIndex.Previous][KeyIndex.Previous];
		if (sess2.isUsedReceivingMACKey)
			oldMacKeys.add(sess2.getReceivingMACKey());

		sessionKeys[KeyIndex.Current][KeyIndex.Previous] = sessionKeys[KeyIndex.Current][KeyIndex.Current];
		sessionKeys[KeyIndex.Previous][KeyIndex.Previous] = sessionKeys[KeyIndex.Previous][KeyIndex.Current];
		sessionKeys[KeyIndex.Current][KeyIndex.Current]
				.setRemoteDHPublicKey(pubKey);
		sessionKeys[KeyIndex.Previous][KeyIndex.Current]
				.setRemoteDHPublicKey(pubKey);
	}

	public void rotateLocalKeys() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			IOException, InvalidKeyException {

		SessionKeys sess1 = sessionKeys[KeyIndex.Previous][KeyIndex.Current];
		if (sess1.isUsedReceivingMACKey)
			oldMacKeys.add(sess1.getReceivingMACKey());

		SessionKeys sess2 = sessionKeys[KeyIndex.Previous][KeyIndex.Previous];
		if (sess2.isUsedReceivingMACKey)
			oldMacKeys.add(sess2.getReceivingMACKey());

		sessionKeys[KeyIndex.Previous][KeyIndex.Current] = sessionKeys[KeyIndex.Current][KeyIndex.Current];
		sessionKeys[KeyIndex.Previous][KeyIndex.Previous] = sessionKeys[KeyIndex.Current][KeyIndex.Previous];

		KeyPair newPair = CryptoUtils.generateDHKeyPair();
		sessionKeys[KeyIndex.Current][KeyIndex.Current].setLocalPair(newPair);
		sessionKeys[KeyIndex.Current][KeyIndex.Previous].setLocalPair(newPair);
	}

}
