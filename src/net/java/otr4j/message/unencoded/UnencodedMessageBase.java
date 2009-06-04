package net.java.otr4j.message.unencoded;

import net.java.otr4j.message.MessageBase;

/**
 * <pre>
 * Unencoded messages
 * 
 * This section describes the messages in the OTR protocol that are not base-64 encoded binary.
 * </pre>
 * 
 * @author george
 * 
 */
public abstract class UnencodedMessageBase extends MessageBase {

	protected UnencodedMessageBase(int messageType) {
		super(messageType);
	}

}
