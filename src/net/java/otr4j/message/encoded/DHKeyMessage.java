package net.java.otr4j.message.encoded;

import java.io.*;
import javax.crypto.interfaces.*;
import net.java.otr4j.message.*;

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
		SerializationUtils.writeDHPublicKey(stream, this.getDhPublicKey());
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException {

		this.setProtocolVersion(DeserializationUtils.readShort(stream));
		this.setMessageType(DeserializationUtils.readByte(stream));
		this.setDhPublicKey(DeserializationUtils.readDHPublicKey(stream));

	}

	public void setDhPublicKey(DHPublicKey dhPublicKey) {
		this.dhPublicKey = dhPublicKey;
	}

	public DHPublicKey getDhPublicKey() {
		return dhPublicKey;
	}
}
