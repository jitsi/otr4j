package net.java.otr4j.message.encoded.signature;

import java.io.IOException;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.DeserializationUtils;
import net.java.otr4j.message.encoded.SerializationUtils;

public final class RevealSignatureMessage extends SignatureMessageBase {

	public RevealSignatureMessage(int protocolVersion, byte[] r, byte[] xEncryptedMAC,
			byte[] xEncrypted) {

		this.messageType = MessageType.REVEALSIG;
		this.protocolVersion = protocolVersion;
		this.xEncryptedMAC = xEncryptedMAC;
		this.xEncrypted = xEncrypted;
		this.revealedKey = r;
	}

	public byte[] revealedKey;

	public RevealSignatureMessage() {

	}

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		SerializationUtils.writeShort(stream, this.protocolVersion);
		SerializationUtils.writeByte(stream, this.messageType);
		SerializationUtils.writeData(stream, this.revealedKey);
		SerializationUtils.writeData(stream, this.xEncrypted);
		SerializationUtils.writeMac(stream, this.xEncryptedMAC);
	}

	public void readObject(java.io.ByteArrayInputStream stream) throws IOException {
		this.protocolVersion = DeserializationUtils.readShort(stream);
		this.messageType = DeserializationUtils.readByte(stream);
		this.revealedKey = DeserializationUtils.readData(stream);
		this.xEncrypted = DeserializationUtils.readData(stream);
		this.xEncryptedMAC = DeserializationUtils.readMac(stream);
	}
}
