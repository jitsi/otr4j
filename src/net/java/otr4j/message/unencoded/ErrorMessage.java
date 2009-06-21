package net.java.otr4j.message.unencoded;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

public final class ErrorMessage extends UnencodedMessageBase {
	public String error;
	
	public ErrorMessage(String msgText){
		if (!msgText.startsWith(MessageHeader.ERROR))
			return;

		this.messageType = MessageType.ERROR;
		this.error = msgText.substring(MessageHeader.ERROR.length());
		
	}
}
