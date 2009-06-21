package net.java.otr4j.message.encoded;

import java.io.IOException;
import net.java.otr4j.message.MessageType;

public final class DHCommitMessage extends EncodedMessageBase {

	public byte[] gxEncrypted;
	public byte[] gxHash;

	public DHCommitMessage() {
	}

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		SerializationUtils.writeShort(stream, this.protocolVersion);
		SerializationUtils.writeByte(stream, this.messageType);
		SerializationUtils.writeData(stream, this.gxEncrypted);
		SerializationUtils.writeData(stream, this.gxHash);
	}

	public void readObject(java.io.ByteArrayInputStream stream) throws IOException {
		this.protocolVersion = DeserializationUtils.readShort(stream);
		this.messageType = DeserializationUtils.readByte(stream);
		this.gxEncrypted = DeserializationUtils.readData(stream);
		this.gxHash = DeserializationUtils.readData(stream);
	}

	public DHCommitMessage(int protocolVersion, byte[] gxHash,
			byte[] gxEncrypted) {

		this.messageType = MessageType.DH_COMMIT;
		this.protocolVersion = protocolVersion;
		this.gxEncrypted = gxEncrypted;
		this.gxHash = gxHash;
	}
}
