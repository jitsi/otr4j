package net.java.otr4j.session;

/**
 * Created by gp on 2/6/14.
 */
public class ProcessedMessage extends Message {

	final Message originalMessage;

	public ProcessedMessage(Message originalMessage, String content) {
		super(originalMessage.getSender(), content);
		this.originalMessage = originalMessage;
	}
}
