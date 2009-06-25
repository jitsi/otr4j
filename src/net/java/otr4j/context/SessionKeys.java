package net.java.otr4j.context;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.crypto.CryptoUtils;

public class SessionKeys {

	public void setLocalPair(KeyPair keyPair) {
		this.localPair = keyPair;
		this.localKeyID = this.localKeyID + 1;
		this.reset();
	}

	public void setRemoteDHPublicKey(DHPublicKey pubKey) {
		this.remoteKey = pubKey;
		this.remoteKeyID = this.remoteKeyID + 1;
		this.reset();
	}

	private void reset() {
		this.sendingAESKey = null;
		this.receivingAESKey = null;
		this.sendingMACKey = null;
		this.receivingMACKey = null;
		this.isUsedReceivingMACKey = false;
		this.s = null;
		if (localPair != null && remoteKey != null)
			this.isHigh = ((DHPublicKey) localPair.getPublic()).getY().abs()
					.compareTo(remoteKey.getY().abs()) == 1;
	}

	public byte[] getSendingAESKey() throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		if (sendingAESKey == null)
			sendingAESKey = CryptoUtils.calculateSendingAESKey(this.isHigh,
					this.getS());
		return sendingAESKey;
	}

	public byte[] getReceivingAESKey() throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		if (receivingAESKey == null)
			receivingAESKey = CryptoUtils.calculateReceivingAESKey(this.isHigh,
					this.getS());
		return receivingAESKey;
	}

	public byte[] getSendingMACKey() throws NoSuchAlgorithmException {
		if (sendingMACKey == null)
			sendingMACKey = CryptoUtils.calculateSendingMACKey(sendingAESKey);
		return sendingMACKey;
	}

	public byte[] getReceivingMACKey() throws NoSuchAlgorithmException {
		if (receivingMACKey == null)
			receivingMACKey = CryptoUtils
					.calculateReceivingMACKey(receivingAESKey);
		return receivingMACKey;
	}

	private BigInteger getS() throws InvalidKeyException,
			NoSuchAlgorithmException {
		if (s == null)
			s = CryptoUtils.generateSecret(localPair.getPrivate(), remoteKey);
		return s;
	}

	public int localKeyID;
	public int remoteKeyID;
	public DHPublicKey remoteKey;
	public KeyPair localPair;

	private byte[] sendingAESKey;
	private byte[] receivingAESKey;
	private byte[] sendingMACKey;
	private byte[] receivingMACKey;
	public Boolean isUsedReceivingMACKey = false;
	private BigInteger s;
	private Boolean isHigh;
}
