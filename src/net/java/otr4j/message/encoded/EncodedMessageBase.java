package net.java.otr4j.message.encoded;

import java.io.ObjectOutputStream;
import java.io.Serializable;

import net.java.otr4j.message.MessageBase;

public abstract class EncodedMessageBase extends MessageBase {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	protected EncodedMessageBase(int messageType) {
		super(messageType);
	}

	public int protocolVersion;
	
	// abstract void writeObject(ObjectOutputStream out);
	// abstract void readObject(ObjectOutputStream in);
	// abstract void validateState();
}
