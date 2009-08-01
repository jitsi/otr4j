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
 */
public interface SessionStatus {
	public static final int PLAINTEXT = 0;
	public static final int ENCRYPTED = 1;
	public static final int FINISHED = 2;
}
