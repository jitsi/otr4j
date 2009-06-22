package net.java.otr4j.message.encoded;

import java.io.IOException;
import net.java.otr4j.message.MessageType;

public final class DHCommitMessage extends EncodedMessageBase {

	private byte[] dhPublicKeyEncrypted;
	private byte[] dhPublicKeyHash;

	public DHCommitMessage() {
	}

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		SerializationUtils.writeShort(stream, this.getProtocolVersion());
		SerializationUtils.writeByte(stream, this.getMessageType());
		SerializationUtils.writeData(stream, this.getDhPublicKeyEncrypted());
		SerializationUtils.writeData(stream, this.getDhPublicKeyHash());
	}

	public void readObject(java.io.ByteArrayInputStream stream) throws IOException {
		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));
		this.setDhPublicKeyEncrypted(DeserializationUtils.readData(stream));
		this.setDhPublicKeyHash(DeserializationUtils.readData(stream));
	}

	public DHCommitMessage(int protocolVersion, byte[] gxHash,
			byte[] gxEncrypted) {

		this.setMessageType(MessageType.DH_COMMIT);
		this.setProtocolVersion(protocolVersion);
		this.setDhPublicKeyEncrypted(gxEncrypted);
		this.setDhPublicKeyHash(gxHash);
	}

	public void setDhPublicKeyHash(byte[] dhPublicKeyHash) {
		this.dhPublicKeyHash = dhPublicKeyHash;
	}

	public byte[] getDhPublicKeyHash() {
		return dhPublicKeyHash;
	}

	public void setDhPublicKeyEncrypted(byte[] dhPublicKeyEncrypted) {
		this.dhPublicKeyEncrypted = dhPublicKeyEncrypted;
	}

	public byte[] getDhPublicKeyEncrypted() {
		return dhPublicKeyEncrypted;
	}
}
