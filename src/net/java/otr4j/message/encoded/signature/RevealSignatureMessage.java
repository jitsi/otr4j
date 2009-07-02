package net.java.otr4j.message.encoded.signature;

import java.io.*;
import net.java.otr4j.message.*;
import net.java.otr4j.message.encoded.*;

public final class RevealSignatureMessage extends SignatureMessageBase {

	public RevealSignatureMessage(int protocolVersion, byte[] r, byte[] xEncryptedMAC,
			byte[] xEncrypted) {

		this.setMessageType(MessageType.REVEALSIG);
		this.setProtocolVersion(protocolVersion);
		this.setXEncryptedMAC(xEncryptedMAC);
		this.setXEncrypted(xEncrypted);
		this.setRevealedKey(r);
	}

	private byte[] revealedKey;

	public RevealSignatureMessage() {

	}

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		SerializationUtils.writeShort(stream, this.getProtocolVersion());
		SerializationUtils.writeByte(stream, this.getMessageType());
		SerializationUtils.writeData(stream, this.getRevealedKey());
		SerializationUtils.writeData(stream, this.getXEncrypted());
		SerializationUtils.writeMac(stream, this.getXEncryptedMAC());
	}

	public void readObject(java.io.ByteArrayInputStream stream) throws IOException {
		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));
		this.setRevealedKey(DeserializationUtils.readData(stream));
		this.setXEncrypted(DeserializationUtils.readData(stream));
		this.setXEncryptedMAC(DeserializationUtils.readMac(stream));
	}

	public void setRevealedKey(byte[] revealedKey) {
		this.revealedKey = revealedKey;
	}

	public byte[] getRevealedKey() {
		return revealedKey;
	}
}
