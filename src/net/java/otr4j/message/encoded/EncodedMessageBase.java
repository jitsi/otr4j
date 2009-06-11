package net.java.otr4j.message.encoded;

import net.java.otr4j.message.MessageBase;

public abstract class EncodedMessageBase extends MessageBase {

	protected EncodedMessageBase(int messageType) {
		super(messageType);
	}

	public int protocolVersion;
}
