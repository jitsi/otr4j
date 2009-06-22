package net.java.otr4j.message.encoded;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import net.java.otr4j.message.MessageBase;

public abstract class EncodedMessageBase extends MessageBase {
	private int protocolVersion;

	public abstract void writeObject(ByteArrayOutputStream stream)
			throws IOException;

	public abstract void readObject(ByteArrayInputStream stream)
			throws IOException;

	public void setProtocolVersion(int protocolVersion) {
		this.protocolVersion = protocolVersion;
	}

	public int getProtocolVersion() {
		return protocolVersion;
	}
}
