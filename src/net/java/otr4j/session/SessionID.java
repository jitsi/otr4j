package net.java.otr4j.session;

public interface SessionID {

	public abstract void setAccountID(String accountID);

	public abstract String getAccountID();

	public abstract String getUserID();

	public abstract String getProtocolName();

}