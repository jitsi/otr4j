package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class DataMessage extends EncodedMessageBase {

	public int flags;
	public int senderKeyID;
	public int recipientKeyID;
	public BigInteger ympi;
	public byte[] ctr;
	public byte[] msg;
	public byte[] mac;
	public byte[] oldKeys;

	public void readObject(ByteArrayInputStream stream) throws IOException {
		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));
		this.flags = DeserializationUtils.readByte(stream);
		this.senderKeyID = DeserializationUtils.readInt(stream);
		this.recipientKeyID = DeserializationUtils.readInt(stream);
		this.ympi = DeserializationUtils.readMpi(stream);
		this.ctr = DeserializationUtils.readCtr(stream);
		this.msg = DeserializationUtils.readData(stream);
		this.mac = DeserializationUtils.readMac(stream);
		this.oldKeys = DeserializationUtils.readData(stream);

	}

	@Override
	public void writeObject(ByteArrayOutputStream stream) throws IOException {
		// TODO Auto-generated method stub

	}
}
