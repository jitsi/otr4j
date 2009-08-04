/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

import java.security.KeyPair;
import net.java.otr4j.session.SessionID;

/**
 * 
 * @author George Politis
 * 
 */
public interface OTR4jListener {
	public void injectMessage(SessionID sessionID, String msg);

	public void showWarning(SessionID sessionID, String warning);

	public void showError(SessionID sessionID, String error);

	public int getPolicy(SessionID sessionID);

	public KeyPair getKeyPair(SessionID sessionID);
}
