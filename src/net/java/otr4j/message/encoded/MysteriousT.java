package net.java.otr4j.message.encoded;

import java.io.*;
import java.security.*;
import java.util.*;
import java.util.logging.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;

import net.java.otr4j.crypto.*;
import net.java.otr4j.message.*;

public class MysteriousT extends EncodedMessageBase {

	private static Logger logger = Logger
			.getLogger(MysteriousT.class.getName());

	private int flags;
	public int senderKeyID;
	public int recipientKeyID;
	public DHPublicKey nextDHPublicKey;
	public byte[] ctr;
	public byte[] encryptedMsg;

	public MysteriousT() {

	}

	public void setFlags(int flags) {
		this.flags = flags;
	}

	public int getFlags() {
		return flags;
	}

	public MysteriousT(int senderKeyID, int receipientKeyID,
			DHPublicKey nextDHPublicKey, byte[] ctr, byte[] encryptedMsg,
			int protocolVersion, int flags) {

		this.setMessageType(MessageType.DATA);
		this.setProtocolVersion(protocolVersion);
		this.setFlags(flags);
		this.senderKeyID = senderKeyID;
		this.recipientKeyID = receipientKeyID;
		this.nextDHPublicKey = nextDHPublicKey;
		this.ctr = ctr;
		this.encryptedMsg = encryptedMsg;
	}

	public void readObject(ByteArrayInputStream in) throws IOException {
		this.setProtocolVersion(DeserializationUtils.readShort(in));
		this.setMessageType(DeserializationUtils.readByte(in));
		this.setFlags(DeserializationUtils.readByte(in));

		senderKeyID = DeserializationUtils.readInt(in);
		recipientKeyID = DeserializationUtils.readInt(in);
		nextDHPublicKey = DeserializationUtils.readDHPublicKey(in);
		ctr = DeserializationUtils.readCtr(in);
		encryptedMsg = DeserializationUtils.readData(in);
	}

	public void writeObject(ByteArrayOutputStream out) throws IOException {
		SerializationUtils.writeShort(out, this.getProtocolVersion());
		SerializationUtils.writeByte(out, this.getMessageType());
		SerializationUtils.writeByte(out, this.getFlags());

		SerializationUtils.writeInt(out, senderKeyID);
		SerializationUtils.writeInt(out, recipientKeyID);
		SerializationUtils.writeDHPublicKey(out, nextDHPublicKey);
		SerializationUtils.writeCtr(out, ctr);
		SerializationUtils.writeData(out, encryptedMsg);
	}

	private String decryptedMessage;

	public String getDecryptedMessage(byte[] key, byte[] ctr)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		decryptedMessage = new String(CryptoUtils.aesDecrypt(key, ctr,
				this.encryptedMsg));
		return decryptedMessage;
	}

	public List<TLV> getTLVs() {
		return null;
	}

	public byte[] hash(byte[] key) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException {
		logger.info("Transforming T to byte[] to calculate it's HmacSHA1.");
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		this.writeObject(out);
		byte[] serializedT = out.toByteArray();
		out.close();

		byte[] computedMAC = CryptoUtils.sha1Hmac(serializedT, key,
				DataLength.MAC);
		return computedMAC;
	}
}
