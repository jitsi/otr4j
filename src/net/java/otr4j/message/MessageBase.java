package net.java.otr4j.message;

public abstract class MessageBase {
	public int messageType;

	protected MessageBase(int messageType) {
		this.messageType = messageType;
	}
}
