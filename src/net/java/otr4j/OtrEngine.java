package net.java.otr4j;

public interface OtrEngine<T> {
	public String handleReceivingMessage(T sessionID, String msgText);

	public String handleSendingMessage(T sessionID, String msgText);

	public void startSession(T sessionID);

	public void endSession(T sessionID);

	public void refreshSession(T sessionID);

	public int getSessionStatus(T sessionID);
}
