package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.interfaces.DHPublicKey;

public class DataMessage extends EncodedMessageBase {

	private int flags;
	private int senderKeyID;
	private int recipientKeyID;
	private DHPublicKey nextDHPublicKey;
	private byte[] ctr;
	private byte[] encryptedMsg;
	private byte[] mac;
	private byte[] oldMACKeys;
	private byte[] t;

	public void readObject(ByteArrayInputStream stream) throws IOException {

		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));
		this.setFlags(DeserializationUtils.readByte(stream));

		this.setT(stream);

		this.setMac(DeserializationUtils.readMac(stream));
		this.setOldMACKeys(DeserializationUtils.readData(stream));
	}

	@Override
	public void writeObject(ByteArrayOutputStream stream) throws IOException {

		SerializationUtils.writeShort(stream, this.getProtocolVersion());
		SerializationUtils.writeByte(stream, this.getMessageType());
		SerializationUtils.writeByte(stream, this.getFlags());

		stream.write(this.getT());

		SerializationUtils.writeMac(stream, this.getMac());
		SerializationUtils.writeData(stream, this.getOldMACKeys());
	}

	public void setFlags(int flags) {
		this.flags = flags;
	}

	public int getFlags() {
		return flags;
	}

	public void setSenderKeyID(int senderKeyID) {
		this.senderKeyID = senderKeyID;
	}

	public int getSenderKeyID() {
		return senderKeyID;
	}

	public void setRecipientKeyID(int recipientKeyID) {
		this.recipientKeyID = recipientKeyID;
	}

	public int getRecipientKeyID() {
		return recipientKeyID;
	}

	public void setNextDHPublicKey(DHPublicKey nextDHPublicKey) {
		this.nextDHPublicKey = nextDHPublicKey;
	}

	public DHPublicKey getNextDHPublicKey() {
		return nextDHPublicKey;
	}

	public void setCtr(byte[] ctr) {
		this.ctr = ctr;
	}

	public byte[] getCtr() {
		return ctr;
	}

	public void setEncryptedMsg(byte[] encryptedMsg) {
		this.encryptedMsg = encryptedMsg;
	}

	public byte[] getEncryptedMsg() {
		return encryptedMsg;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

	public byte[] getMac() {
		return mac;
	}

	public void setOldMACKeys(byte[] oldMACKeys) {
		this.oldMACKeys = oldMACKeys;
	}

	public byte[] getOldMACKeys() {
		return oldMACKeys;
	}

	private void setT(ByteArrayInputStream stream) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		this.setSenderKeyID(DeserializationUtils.readInt(stream, out));
		this.setRecipientKeyID(DeserializationUtils.readInt(stream, out));
		this.setNextDHPublicKey(DeserializationUtils.readDHPublicKey(stream,
				out));
		this.setCtr(DeserializationUtils.readCtr(stream, out));
		this.setEncryptedMsg(DeserializationUtils.readData(stream, out));
		this.t = out.toByteArray();
		out.close();
	}

	public byte[] getT() throws IOException {
		if (this.t != null)
			return this.t;

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		SerializationUtils.writeInt(out, this.getSenderKeyID());
		SerializationUtils.writeInt(out, this.getRecipientKeyID());
		SerializationUtils.writeDHPublicKey(out, this.getNextDHPublicKey());
		SerializationUtils.writeCtr(out, this.getCtr());
		SerializationUtils.writeData(out, this.getEncryptedMsg());
		t = out.toByteArray();
		out.close();
		return t;
	}
}
