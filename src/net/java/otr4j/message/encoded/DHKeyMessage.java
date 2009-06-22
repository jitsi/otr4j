package net.java.otr4j.message.encoded;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.MessageType;

public final class DHKeyMessage extends EncodedMessageBase {

	public DHPublicKey dhPublicKey;

	public DHKeyMessage() {

	}

	public DHKeyMessage(int protocolVersion, DHPublicKey dhPublicKey) {
		this.messageType = MessageType.DH_KEY;
		this.dhPublicKey = dhPublicKey;
		this.protocolVersion = protocolVersion;
	}

	public void writeObject(ByteArrayOutputStream stream) throws IOException {

		SerializationUtils.writeShort(stream, this.protocolVersion);
		SerializationUtils.writeByte(stream, this.messageType);
		SerializationUtils.writeMpi(stream, this.dhPublicKey.getY());
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException {

		this.protocolVersion = DeserializationUtils.readShort(stream);
		this.messageType = DeserializationUtils.readByte(stream);

		BigInteger gyMpi = DeserializationUtils.readMpi(stream);
		try {
			this.dhPublicKey = CryptoUtils.getDHPublicKey(gyMpi);
		} catch (Exception e) {
			throw new IOException(e);
		}
	}
}
