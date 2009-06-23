package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.crypto.interfaces.DHPublicKey;

public class DataMessage extends EncodedMessageBase {

	public int flags;
	public int senderKeyID;
	public int recipientKeyID;
	public DHPublicKey nextDHPublicKey;
	public byte[] ctr;
	public byte[] encryptedMsg;
	public byte[] mac;
	public byte[] oldMACKeys;
	public byte[] t;

	public void readObject(ByteArrayInputStream stream) throws IOException {

		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));
		this.flags = DeserializationUtils.readByte(stream);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		this.senderKeyID = DeserializationUtils.readInt(stream, out);
		this.recipientKeyID = DeserializationUtils.readInt(stream, out);
		this.nextDHPublicKey = DeserializationUtils
				.readDHPublicKey(stream, out);
		this.ctr = DeserializationUtils.readCtr(stream, out);
		this.encryptedMsg = DeserializationUtils.readData(stream, out);
		this.t = out.toByteArray();

		this.mac = DeserializationUtils.readMac(stream);
		this.oldMACKeys = DeserializationUtils.readData(stream);
	}

	@Override
	public void writeObject(ByteArrayOutputStream stream) throws IOException {

		SerializationUtils.writeShort(stream, this.getProtocolVersion());
		SerializationUtils.writeByte(stream, this.getMessageType());
		SerializationUtils.writeByte(stream, this.flags);

		SerializationUtils.writeInt(stream, this.senderKeyID);
		SerializationUtils.writeInt(stream, this.recipientKeyID);
		SerializationUtils.writeDHPublicKey(stream, this.nextDHPublicKey);
		SerializationUtils.writeCtr(stream, this.ctr);
		SerializationUtils.writeData(stream, this.encryptedMsg);

		SerializationUtils.writeMac(stream, this.mac);
		SerializationUtils.writeData(stream, this.oldMACKeys);
	}
}
