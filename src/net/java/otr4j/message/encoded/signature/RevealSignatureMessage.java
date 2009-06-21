package net.java.otr4j.message.encoded.signature;

import java.io.IOException;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.DeserializationUtils;
import net.java.otr4j.message.encoded.SerializationUtils;

public final class RevealSignatureMessage extends SignatureMessageBase {

	public RevealSignatureMessage(int protocolVersion, byte[] r, byte[] mac,
			byte[] XBEncrypted) {

		this.messageType = MessageType.REVEALSIG;
		this.protocolVersion = protocolVersion;
		this.signatureMac = mac;
		this.encryptedSignature = XBEncrypted;
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
		SerializationUtils.writeData(stream, this.encryptedSignature);
		SerializationUtils.writeMac(stream, this.signatureMac);
	}

	public void readObject(java.io.ByteArrayInputStream stream) throws IOException {
		this.protocolVersion = DeserializationUtils.readShort(stream);
		this.messageType = DeserializationUtils.readByte(stream);
		this.revealedKey = DeserializationUtils.readData(stream);
		this.encryptedSignature = DeserializationUtils.readData(stream);
		this.signatureMac = DeserializationUtils.readMac(stream);
	}
}
