package net.java.otr4j.message.unencoded;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

/**
 * <pre>
 * OTR Error Messages
 * 
 * Any message containing the string &quot;?OTR Error:&quot; is an OTR Error Message. The following part of the message should contain human-readable details of the error.
 * </pre>
 * 
 * @author george
 * 
 */
public final class ErrorMessage extends UnencodedMessageBase {
	private ErrorMessage() {
		super(MessageType.ERROR);
	}

	private String error;

	private void setError(String error) {
		this.error = error;
	}

	public String getError() {
		return error;
	}
	
	public static ErrorMessage disassemble(String msgText){
		if (!msgText.startsWith(MessageHeader.ERROR))
			return null;

		ErrorMessage msg = new ErrorMessage();
		msg.setError(msgText.substring(MessageHeader.ERROR.length()));
		return msg;
		
	}
}
