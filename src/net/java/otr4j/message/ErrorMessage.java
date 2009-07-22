/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

/**
 * 
 * @author George Politis
 */
public final class ErrorMessage extends MessageBase {
	public String error;
	
	public ErrorMessage(String msgText){
		super(MessageConstants.ERROR);
		
		if (!msgText.startsWith(MessageConstants.ERROR_HEAD))
			return;
		this.error = msgText.substring(MessageConstants.ERROR_HEAD.length());
	}
	
	public String toString(){
		return MessageConstants.ERROR_HEAD + error;
	}
}
