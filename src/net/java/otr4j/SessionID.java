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
 * 
 */
public final class SessionID {

	public SessionID(String accountID, String userID, String protocolName) {
		this.setAccountID(accountID);
		this.setUserID(userID);
		this.setProtocolName(protocolName);
	}

	private String accountID;
	private String userID;
	private String protocolName;

	public void setAccountID(String accountID) {
		this.accountID = accountID;
	}

	public String getAccountID() {
		return accountID;
	}

	private void setUserID(String userID) {
		this.userID = userID;
	}

	public String getUserID() {
		return userID;
	}

	private void setProtocolName(String protocolName) {
		this.protocolName = protocolName;
	}

	public String getProtocolName() {
		return protocolName;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (!(obj instanceof SessionID))
			return false;

		SessionID sessionID = (SessionID) obj;

		return this.getAccountID().equals(sessionID.getAccountID())
				&& this.getUserID().equals(sessionID.getUserID())
				&& this.getProtocolName().equals(sessionID.getProtocolName());
	}

	@Override
	public int hashCode() {
		return this.getAccountID().hashCode() + this.getUserID().hashCode()
				+ this.getProtocolName().hashCode();
	}
}
