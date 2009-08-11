/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

import java.security.KeyPair;

import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;

/**
 * 
 * @author George Politis
 * 
 */
public interface OtrEngineListener {
	public abstract void injectMessage(SessionID sessionID, String msg);

	public abstract void showWarning(SessionID sessionID, String warning);

	public abstract void showError(SessionID sessionID, String error);

	public abstract OtrPolicy getPolicy(SessionID sessionID);

	public abstract KeyPair getKeyPair(SessionID sessionID);
	
	public abstract Boolean getSessionIsAuthenticated(SessionID sessionID);
	
	public abstract void sessionStatusChanged(SessionID sessionID, SessionStatus status);
}
