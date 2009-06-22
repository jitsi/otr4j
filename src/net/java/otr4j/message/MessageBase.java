package net.java.otr4j.message;

public abstract class MessageBase {
	private int messageType;

	public void setMessageType(int messageType) {
		this.messageType = messageType;
	}

	public int getMessageType() {
		return messageType;
	}
}
