package net.java.otr4j.context;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
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

	public ByteArrayOutputStream oldMacKeys = new ByteArrayOutputStream();
	public void rotateRemoteKeys(DHPublicKey pubKey)
			throws NoSuchAlgorithmException, IOException {

		oldMacKeys.write(sessionKeys[KeyIndex.Current][KeyIndex.Previous]
				.getSendingMACKey());
		oldMacKeys.write(sessionKeys[KeyIndex.Current][KeyIndex.Previous]
				.getReceivingMACKey());
		oldMacKeys.write(sessionKeys[KeyIndex.Previous][KeyIndex.Previous]
				.getSendingMACKey());
		oldMacKeys.write(sessionKeys[KeyIndex.Current][KeyIndex.Previous]
				.getReceivingMACKey());

		sessionKeys[KeyIndex.Current][KeyIndex.Previous] = sessionKeys[KeyIndex.Current][KeyIndex.Current];
		sessionKeys[KeyIndex.Previous][KeyIndex.Previous] = sessionKeys[KeyIndex.Previous][KeyIndex.Current];
		sessionKeys[KeyIndex.Current][KeyIndex.Current]
				.setRemoteDHPublicKey(pubKey);
		sessionKeys[KeyIndex.Previous][KeyIndex.Current]
				.setRemoteDHPublicKey(pubKey);
	}

	public void rotateLocalKeys() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			IOException {

		oldMacKeys.write(sessionKeys[KeyIndex.Previous][KeyIndex.Current]
				.getSendingMACKey());
		oldMacKeys.write(sessionKeys[KeyIndex.Previous][KeyIndex.Current]
				.getReceivingMACKey());
		oldMacKeys.write(sessionKeys[KeyIndex.Previous][KeyIndex.Previous]
				.getSendingMACKey());
		oldMacKeys.write(sessionKeys[KeyIndex.Previous][KeyIndex.Previous]
				.getReceivingMACKey());

		sessionKeys[KeyIndex.Previous][KeyIndex.Current] = sessionKeys[KeyIndex.Current][KeyIndex.Current];
		sessionKeys[KeyIndex.Previous][KeyIndex.Previous] = sessionKeys[KeyIndex.Current][KeyIndex.Previous];

		KeyPair newPair = CryptoUtils.generateDHKeyPair();
		sessionKeys[KeyIndex.Current][KeyIndex.Current].setLocalPair(newPair);
		sessionKeys[KeyIndex.Current][KeyIndex.Previous].setLocalPair(newPair);
	}
}
