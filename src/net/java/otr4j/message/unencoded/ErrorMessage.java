package net.java.otr4j.message.unencoded;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

public final class ErrorMessage extends UnencodedMessageBase {
	private ErrorMessage() {
		super(MessageType.ERROR);
	}

	public String error;
	
	public ErrorMessage(String msgText){
		this();
		
		if (!msgText.startsWith(MessageHeader.ERROR))
			return;

		this.error = msgText.substring(MessageHeader.ERROR.length());
		
	}
}
