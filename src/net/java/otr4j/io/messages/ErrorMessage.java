/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import java.io.IOException;

/**
 * 
 * @author George Politis
 */
public final class ErrorMessage extends MessageBase {
	public String error;
	
	public ErrorMessage(){
		super(MessageConstants.ERROR);
	}
	
	public ErrorMessage(String error){
		super(MessageConstants.ERROR);
		this.error = error;
	}

	public void readObject(String msg) throws IOException {
		this.error = msg.substring(MessageConstants.ERROR_HEAD.length());
	}

	public String writeObject() throws IOException {
		return MessageConstants.ERROR_HEAD + error;
	}
}
