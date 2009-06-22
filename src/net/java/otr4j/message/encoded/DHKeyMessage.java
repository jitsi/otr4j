package net.java.otr4j.message.encoded;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.MessageType;

public final class DHKeyMessage extends EncodedMessageBase {

	private DHPublicKey dhPublicKey;

	public DHKeyMessage() {

	}

	public DHKeyMessage(int protocolVersion, DHPublicKey dhPublicKey) {
		this.setMessageType(MessageType.DH_KEY);
		this.setDhPublicKey(dhPublicKey);
		this.setProtocolVersion(protocolVersion);
	}

	public void writeObject(ByteArrayOutputStream stream) throws IOException {

		SerializationUtils.writeShort(stream, this.getProtocolVersion());
		SerializationUtils.writeByte(stream, this.getMessageType());
		SerializationUtils.writeMpi(stream, this.getDhPublicKey().getY());
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException {

		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));

		BigInteger gyMpi = DeserializationUtils.readMpi(stream);
		try {
			this.setDhPublicKey(CryptoUtils.getDHPublicKey(gyMpi));
		} catch (Exception e) {
			throw new IOException(e);
		}
	}

	public void setDhPublicKey(DHPublicKey dhPublicKey) {
		this.dhPublicKey = dhPublicKey;
	}

	public DHPublicKey getDhPublicKey() {
		return dhPublicKey;
	}
}
