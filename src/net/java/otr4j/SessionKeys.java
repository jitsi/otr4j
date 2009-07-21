/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

import java.io.*;
import java.math.*;
import java.nio.*;
import java.security.*;
import java.util.*;
import java.util.logging.*;
import javax.crypto.interfaces.*;

import net.java.otr4j.message.*;

/**
 * 
 * @author George Politis
 */
class SessionKeys {

	public static final int Previous = 0;
	public static final int Current = 1;
	public static final byte HIGH_SEND_BYTE = (byte)0x01;
	public static final byte HIGH_RECEIVE_BYTE = (byte)0x02;
	public static final byte LOW_SEND_BYTE = (byte)0x02;
	public static final byte LOW_RECEIVE_BYTE = (byte)0x01;
	
	private static Logger logger = Logger
			.getLogger(SessionKeys.class.getName());
	private String keyDescription;

	SessionKeys(int localKeyIndex, int remoteKeyIndex) {
		if (localKeyIndex == 0)
			keyDescription = "(Previous local, ";
		else
			keyDescription = "(Most recent local, ";

		if (remoteKeyIndex == 0)
			keyDescription += "Previous remote)";
		else
			keyDescription += "Most recent remote)";

	}

	void setLocalPair(KeyPair keyPair, int localPairKeyID) {
		this.localPair = keyPair;
		this.setLocalKeyID(localPairKeyID);
		logger.info(keyDescription + " current local key ID: "
				+ this.getLocalKeyID());
		this.reset();
	}

	void setRemoteDHPublicKey(DHPublicKey pubKey, int remoteKeyID) {
		this.setRemoteKey(pubKey);
		this.setRemoteKeyID(remoteKeyID);
		logger.info(keyDescription + " current remote key ID: "
				+ this.getRemoteKeyID());
		this.reset();
	}

	private byte[] sendingCtr = new byte[16];
	private byte[] receivingCtr = new byte[16];

	void incrementSendingCtr() {
		logger.info("Incrementing counter for (localkeyID, remoteKeyID) = ("
				+ getLocalKeyID() + "," + getRemoteKeyID() + ")");
		// logger.debug("Counter prior increament: " +
		// Utils.dump(sendingCtr,
		// true, 16));
		for (int i = 7; i >= 0; i--)
			if (++sendingCtr[i] != 0)
				break;
		// logger.debug("Counter after increament: " +
		// Utils.dump(sendingCtr,
		// true, 16));
	}

	byte[] getSendingCtr() {
		return sendingCtr;
	}

	byte[] getReceivingCtr() {
		return receivingCtr;
	}

	void setReceivingCtr(byte[] ctr) {
		for (int i = 0; i < ctr.length; i++)
			receivingCtr[i] = ctr[i];
	}

	private void reset() {
		logger.info("Resetting " + keyDescription + " session keys.");
		Arrays.fill(this.sendingCtr, (byte) 0x00);
		Arrays.fill(this.receivingCtr, (byte) 0x00);
		this.sendingAESKey = null;
		this.receivingAESKey = null;
		this.sendingMACKey = null;
		this.receivingMACKey = null;
		this.setIsUsedReceivingMACKey(false);
		this.s = null;
		if (getLocalPair() != null && getRemoteKey() != null) {
			this.isHigh = ((DHPublicKey) getLocalPair().getPublic()).getY()
					.abs().compareTo(getRemoteKey().getY().abs()) == 1;
		}

	}

	private byte[] h1(byte b) throws NoSuchAlgorithmException, IOException,
			InvalidKeyException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		SerializationUtils.writeMpi(bos, getS());
		byte[] secbytes = bos.toByteArray();
		bos.close();

		int len = secbytes.length + 1;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(b);
		buff.put(secbytes);
		byte[] result = CryptoUtils.sha1Hash(buff.array());
		return result;
	}

	byte[] getSendingAESKey() throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		if (sendingAESKey != null)
			return sendingAESKey;

		byte sendbyte = LOW_SEND_BYTE;
		if (this.isHigh)
			sendbyte = HIGH_SEND_BYTE;

		byte[] h1 = h1(sendbyte);

		byte[] key = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		ByteBuffer buff = ByteBuffer.wrap(h1);
		buff.get(key);
		logger.info("Calculated sending AES key.");
		this.sendingAESKey = key;
		return sendingAESKey;
	}

	byte[] getReceivingAESKey() throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		if (receivingAESKey != null)
			return receivingAESKey;

		byte receivebyte = LOW_RECEIVE_BYTE;
		if (this.isHigh)
			receivebyte = HIGH_RECEIVE_BYTE;

		byte[] h1 = h1(receivebyte);

		byte[] key = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		ByteBuffer buff = ByteBuffer.wrap(h1);
		buff.get(key);
		logger.info("Calculated receiving AES key.");
		this.receivingAESKey = key;

		return receivingAESKey;
	}

	byte[] getSendingMACKey() throws NoSuchAlgorithmException,
			InvalidKeyException, IOException {
		if (sendingMACKey != null)
			return sendingAESKey;

		sendingMACKey = CryptoUtils.sha1Hash(getSendingAESKey());
		logger.info("Calculated sending MAC key.");
		return sendingMACKey;
	}

	byte[] getReceivingMACKey() throws NoSuchAlgorithmException,
			InvalidKeyException, IOException {
		if (receivingMACKey == null) {
			receivingMACKey = CryptoUtils.sha1Hash(getReceivingAESKey());
			logger.info("Calculated receiving AES key.");
		}
		return receivingMACKey;
	}

	private BigInteger getS() throws InvalidKeyException,
			NoSuchAlgorithmException {
		if (s == null) {
			s = CryptoUtils.generateSecret(getLocalPair().getPrivate(),
					getRemoteKey());
			logger.info("Calculating shared secret S.");
		}
		return s;
	}

	void setS(BigInteger s) {
		this.s = s;
	}

	void setIsUsedReceivingMACKey(Boolean isUsedReceivingMACKey) {
		this.isUsedReceivingMACKey = isUsedReceivingMACKey;
	}

	Boolean getIsUsedReceivingMACKey() {
		return isUsedReceivingMACKey;
	}

	private void setLocalKeyID(int localKeyID) {
		this.localKeyID = localKeyID;
	}

	int getLocalKeyID() {
		return localKeyID;
	}

	private void setRemoteKeyID(int remoteKeyID) {
		this.remoteKeyID = remoteKeyID;
	}

	int getRemoteKeyID() {
		return remoteKeyID;
	}

	private void setRemoteKey(DHPublicKey remoteKey) {
		this.remoteKey = remoteKey;
	}

	DHPublicKey getRemoteKey() {
		return remoteKey;
	}

	KeyPair getLocalPair() {
		return localPair;
	}

	private int localKeyID;
	private int remoteKeyID;
	private DHPublicKey remoteKey;
	private KeyPair localPair;

	private byte[] sendingAESKey;
	private byte[] receivingAESKey;
	private byte[] sendingMACKey;
	private byte[] receivingMACKey;
	private Boolean isUsedReceivingMACKey;
	private BigInteger s;
	private Boolean isHigh;
}
