package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import net.java.otr4j.message.MessageType;

public class DataMessage extends EncodedMessageBase {

	private int flags;
	private byte[] mac;
	private byte[] oldMACKeys;
	public MysteriousT t;

	public DataMessage() {

	}

	public DataMessage(int protocolVersion, int flags, MysteriousT t,
			byte[] mac, byte[] oldMacKeys) {

		this.setMessageType(MessageType.DATA);
		this.setProtocolVersion(protocolVersion);
		this.setFlags(flags);
		this.setMac(mac);
		this.t = t;
		this.setOldMACKeys(oldMacKeys);
	}

	public void readObject(ByteArrayInputStream stream) throws IOException {

		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));
		this.setFlags(DeserializationUtils.readByte(stream));

		t = new MysteriousT();
		t.readObject(stream);

		this.setMac(DeserializationUtils.readMac(stream));
		this.setOldMACKeys(DeserializationUtils.readData(stream));
	}

	@Override
	public void writeObject(ByteArrayOutputStream stream) throws IOException {

		SerializationUtils.writeShort(stream, this.getProtocolVersion());
		SerializationUtils.writeByte(stream, this.getMessageType());
		SerializationUtils.writeByte(stream, this.getFlags());

		t.writeObject(stream);

		SerializationUtils.writeMac(stream, this.getMac());
		SerializationUtils.writeData(stream, this.getOldMACKeys());
	}

	public void setFlags(int flags) {
		this.flags = flags;
	}

	public int getFlags() {
		return flags;
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
}
