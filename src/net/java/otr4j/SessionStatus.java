/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

/**
 * 
 * @author George Politis
 */
public class SessionStatus {

	public SessionStatus(int messageState) {
		this.setMessageState(messageState);
	}

	private int messageState;

	private void setMessageState(int messageState) {
		this.messageState = messageState;
	}

	public int getMessageState() {
		return messageState;
	}
}
