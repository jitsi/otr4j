package net.java.otr4j.context;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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

	private byte[] sendingCtr = new byte[16];
	private byte[] receivingCtr = new byte[16];

	public void incrementSendingCtr() {
		for (int i = 7; i >= 0; i--)
			if (++sendingCtr[i] != 0)
				break;
	}

	public byte[] getSendingCtr() {
		return sendingCtr;
	}

	public byte[] getReceivingCtr() {
		return receivingCtr;
	}

	public void setReceivingCtr(byte[] ctr) {
		for (int i = 0; i < ctr.length; i++)
			receivingCtr[i] = ctr[i];
	}

	private void reset() {
		Arrays.fill(this.sendingCtr, (byte) 0x00);
		Arrays.fill(this.receivingCtr, (byte) 0x00);
		this.sendingAESKey = null;
		this.receivingAESKey = null;
		this.sendingMACKey = null;
		this.receivingMACKey = null;
		this.isUsedReceivingMACKey = false;
		this.s = null;
		if (localPair != null && remoteKey != null) {
			this.isHigh = ((DHPublicKey) localPair.getPublic()).getY().abs()
					.compareTo(remoteKey.getY().abs()) == 1;
		}

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

	public byte[] getSendingMACKey() throws NoSuchAlgorithmException,
			InvalidKeyException, IOException {
		if (sendingMACKey == null)
			sendingMACKey = CryptoUtils.calculateSendingMACKey(this
					.getSendingAESKey());
		return sendingMACKey;
	}

	public byte[] getReceivingMACKey() throws NoSuchAlgorithmException,
			InvalidKeyException, IOException {
		if (receivingMACKey == null)
			receivingMACKey = CryptoUtils.calculateReceivingMACKey(this
					.getReceivingAESKey());
		return receivingMACKey;
	}

	private BigInteger getS() throws InvalidKeyException,
			NoSuchAlgorithmException {
		if (s == null)
			s = CryptoUtils.generateSecret(localPair.getPrivate(), remoteKey);
		return s;
	}

	public void setS(BigInteger s) {
		this.s = s;
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
