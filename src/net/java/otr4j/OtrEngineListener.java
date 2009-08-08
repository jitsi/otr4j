/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

import java.security.KeyPair;

/**
 * 
 * @author George Politis
 * 
 */
public interface OtrEngineListener<T> {
	public abstract void injectMessage(T sessionID, String msg);

	public abstract  void showWarning(T sessionID, String warning);

	public abstract  void showError(T sessionID, String error);

	public abstract  int getPolicy(T sessionID);

	public abstract  KeyPair getKeyPair(T sessionID);
}
