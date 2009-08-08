/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

/**
 * 
 * @author George Politis
 * 
 */
public final class SessionIDImpl {

	public static final SessionIDImpl Empty = new SessionIDImpl(null, null, null);

	public SessionIDImpl(String accountID, String userID, String protocolName) {
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
		if (accountID == null)
			accountID = "";
		return accountID;
	}

	private void setUserID(String userID) {
		this.userID = userID;
	}

	public String getUserID() {
		if (userID == null)
			userID = "";		
		return userID;
	}

	private void setProtocolName(String protocolName) {
		this.protocolName = protocolName;
	}

	public String getProtocolName() {
		if (protocolName == null)
			protocolName = "";
		return protocolName;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (obj == null || obj.getClass() != this.getClass())
			return false;

		SessionIDImpl sessionID = (SessionIDImpl) obj;
		
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
