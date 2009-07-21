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
public abstract class MessageBase {
	public MessageBase(int messageType){
		setMessageType(messageType);
	}
	
	private int messageType;

	public void setMessageType(int messageType) {
		this.messageType = messageType;
	}

	public int getMessageType() {
		return messageType;
	}
}
