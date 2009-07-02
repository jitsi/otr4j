package net.java.otr4j.context;

import java.io.*;
import java.math.*;
import java.nio.*;
import java.security.*;
import java.util.*;

import javax.crypto.interfaces.*;

import org.apache.log4j.*;

import net.java.otr4j.crypto.*;
import net.java.otr4j.message.encoded.*;

public class SessionKeys {

	private static Logger logger = Logger.getLogger(SessionKeys.class);

	private String keyDescription;

	public SessionKeys(int localKeyIndex, int remoteKeyIndex) {
		if (localKeyIndex == 0)
			keyDescription = "(Previous local, ";
		else
			keyDescription = "(Most recent local, ";

		if (remoteKeyIndex == 0)
			keyDescription += "Previous remote)";
		else
			keyDescription += "Most recent remote)";

	}

	public void setLocalPair(KeyPair keyPair, int localPairKeyID) {
		this.localPair = keyPair;
		this.localKeyID = localPairKeyID;
		logger.info(keyDescription + " current local key ID: "
				+ this.localKeyID);
		this.reset();
	}

	public void setRemoteDHPublicKey(DHPublicKey pubKey, int remoteKeyID) {
		this.remoteKey = pubKey;
		this.remoteKeyID = remoteKeyID;
		logger.info(keyDescription + " current remote key ID: "
				+ this.remoteKeyID);
		this.reset();
	}

	private byte[] sendingCtr = new byte[16];
	private byte[] receivingCtr = new byte[16];

	public void incrementSendingCtr() {
		logger.info("Incrementing counter for (localkeyID, remoteKeyID) = ("
				+ localKeyID + "," + remoteKeyID + ")");
		//logger.debug("Counter prior increament: "				+ Utils.dump(sendingCtr, true, 16));
		for (int i = 7; i >= 0; i--)
			if (++sendingCtr[i] != 0)
				break;
		//logger.debug("Counter after increament: "				+ Utils.dump(sendingCtr, true, 16));
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
		logger.info("Resetting " + keyDescription + " session keys.");
		Arrays.fill(this.sendingCtr, (byte) 0x00);
		Arrays.fill(this.receivingCtr, (byte) 0x00);
		this.sendingAESKey = null;
		this.receivingAESKey = null;
		this.sendingMACKey = null;
		this.receivingMACKey = null;
		this.setIsUsedReceivingMACKey(false);
		this.s = null;
		if (localPair != null && remoteKey != null) {
			this.isHigh = ((DHPublicKey) localPair.getPublic()).getY().abs()
					.compareTo(remoteKey.getY().abs()) == 1;
		}

	}

	private static byte[] h1(byte b, BigInteger s)
			throws NoSuchAlgorithmException, IOException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		SerializationUtils.writeMpi(bos, s);
		byte[] secbytes = bos.toByteArray();
		bos.close();

		int len = secbytes.length + 1;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(b);
		buff.put(secbytes);
		byte[] result = CryptoUtils.sha1Hash(buff.array());
		return result;
	}

	public byte[] getSendingAESKey() throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		if (sendingAESKey != null)
			return sendingAESKey;

		byte sendbyte = CryptoConstants.LOW_SEND_BYTE;
		if (this.isHigh)
			sendbyte = CryptoConstants.HIGH_SEND_BYTE;

		byte[] h1 = h1(sendbyte, this.getS());

		byte[] key = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		ByteBuffer buff = ByteBuffer.wrap(h1);
		buff.get(key);
		logger.info("Calculated sending AES key.");
		this.sendingAESKey = key;
		return sendingAESKey;
	}

	public byte[] getReceivingAESKey() throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		if (receivingAESKey != null)
			return receivingAESKey;

		byte receivebyte = CryptoConstants.LOW_RECEIVE_BYTE;
		if (this.isHigh)
			receivebyte = CryptoConstants.HIGH_RECEIVE_BYTE;

		byte[] h1 = h1(receivebyte, this.getS());

		byte[] key = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		ByteBuffer buff = ByteBuffer.wrap(h1);
		buff.get(key);
		logger.info("Calculated receiving AES key.");
		this.receivingAESKey = key;

		return receivingAESKey;
	}

	public byte[] getSendingMACKey() throws NoSuchAlgorithmException,
			InvalidKeyException, IOException {
		if (sendingMACKey != null)
			return sendingAESKey;

		sendingMACKey = CryptoUtils.sha1Hash(getSendingAESKey());
		logger.info("Calculated sending MAC key.");
		return sendingMACKey;
	}

	public byte[] getReceivingMACKey() throws NoSuchAlgorithmException,
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
			s = CryptoUtils.generateSecret(localPair.getPrivate(), remoteKey);
			logger.info("Calculating shared secret S.");
		}
		return s;
	}

	public void setS(BigInteger s) {
		this.s = s;
	}

	public void setIsUsedReceivingMACKey(Boolean isUsedReceivingMACKey) {
		this.isUsedReceivingMACKey = isUsedReceivingMACKey;
	}

	public Boolean getIsUsedReceivingMACKey() {
		return isUsedReceivingMACKey;
	}

	public int localKeyID;
	public int remoteKeyID;
	public DHPublicKey remoteKey;
	public KeyPair localPair;

	private byte[] sendingAESKey;
	private byte[] receivingAESKey;
	private byte[] sendingMACKey;
	private byte[] receivingMACKey;
	private Boolean isUsedReceivingMACKey = false;
	private BigInteger s;
	private Boolean isHigh;
}
