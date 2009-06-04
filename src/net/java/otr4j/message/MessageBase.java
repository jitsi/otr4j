package net.java.otr4j.message;

public abstract class MessageBase {
	// PRIVATE MEMBERS
	private int messageType;
	
	// GETTERS/SETTERS
	protected void setMessageType(int messageType) {
		this.messageType = messageType;
	}

	public int getMessageType() {
		return messageType;
	}
	
	// PUBLIC METHODS
	protected MessageBase(int messageType) {
		this.setMessageType(messageType);
	}
}
