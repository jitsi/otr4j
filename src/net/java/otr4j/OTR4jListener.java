/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * 
 * @author George Politis
 * 
 */
public interface OTR4jListener {
	public void injectMessage(String msg, String account, String user,
			String protocol);

	public void showWarning(String warning);

	public void showError(String error);

	public int getPolicy(ConnContext ctx);

	public KeyPair getKeyPair(String account, String protocol)
			throws NoSuchAlgorithmException;
}
