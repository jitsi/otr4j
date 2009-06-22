package net.java.otr4j.message.encoded;

import java.io.IOException;
import net.java.otr4j.message.MessageType;

public final class DHCommitMessage extends EncodedMessageBase {

	public byte[] dhPublicKeyEncrypted;
	public byte[] dhPublicKeyHash;

	public DHCommitMessage() {
	}

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		SerializationUtils.writeShort(stream, this.protocolVersion);
		SerializationUtils.writeByte(stream, this.messageType);
		SerializationUtils.writeData(stream, this.dhPublicKeyEncrypted);
		SerializationUtils.writeData(stream, this.dhPublicKeyHash);
	}

	public void readObject(java.io.ByteArrayInputStream stream) throws IOException {
		this.protocolVersion = DeserializationUtils.readShort(stream);
		this.messageType = DeserializationUtils.readByte(stream);
		this.dhPublicKeyEncrypted = DeserializationUtils.readData(stream);
		this.dhPublicKeyHash = DeserializationUtils.readData(stream);
	}

	public DHCommitMessage(int protocolVersion, byte[] gxHash,
			byte[] gxEncrypted) {

		this.messageType = MessageType.DH_COMMIT;
		this.protocolVersion = protocolVersion;
		this.dhPublicKeyEncrypted = gxEncrypted;
		this.dhPublicKeyHash = gxHash;
	}
}
