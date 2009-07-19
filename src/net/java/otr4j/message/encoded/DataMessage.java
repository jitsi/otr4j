package net.java.otr4j.message.encoded;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class DataMessage {

	private byte[] mac;
	private byte[] oldMACKeys;
	public MysteriousT t;

	public DataMessage() {

	}

	public DataMessage(MysteriousT t, byte[] mac, byte[] oldMacKeys) {

		this.setMac(mac);
		this.t = t;
		this.setOldMACKeys(oldMacKeys);
	}

	public void readObject(ByteArrayInputStream stream) throws IOException {
		t = new MysteriousT();
		t.readObject(stream);

		this.setMac(DeserializationUtils.readMac(stream));
		this.setOldMACKeys(DeserializationUtils.readData(stream));
	}

	public void writeObject(ByteArrayOutputStream stream) throws IOException {

		t.writeObject(stream);

		SerializationUtils.writeMac(stream, this.getMac());
		SerializationUtils.writeData(stream, this.getOldMACKeys());
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

	public String toUnsafeString() throws IOException {
		ByteArrayOutputStream bos = null;
		try {
			bos = new ByteArrayOutputStream();
			this.writeObject(bos);

			String encodedMessage = EncodedMessageUtils.encodeMessage(bos
					.toByteArray());
			return encodedMessage;
		} finally {
			bos.close();
		}
	}

	public Boolean verify(byte[] key) throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		byte[] computedMAC = t.hash(key);

		return Arrays.equals(computedMAC, this.getMac());
	}
}
