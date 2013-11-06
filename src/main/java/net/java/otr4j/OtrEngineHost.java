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
 * This interface should be implemented by the host application. It is required
 * for otr4j to work properly.
 * 
 * @author George Politis
 * 
 */
public abstract interface OtrEngineHost {
	public abstract void injectMessage(SessionID sessionID, String msg)
			throws OtrException;

	public abstract void unreadableMessageReceived(SessionID sessionID)
			throws OtrException;

	public abstract void unencryptedMessageReceived(SessionID sessionID,
			String msg) throws OtrException;

	public abstract void showError(SessionID sessionID, String error)
			throws OtrException;

	public abstract void smpError(SessionID sessionID, int tlvType,
			boolean cheated) throws OtrException;

	public abstract void smpAborted(SessionID sessionID) throws OtrException;

	public abstract void finishedSessionMessage(SessionID sessionID)
			throws OtrException;

	public abstract void requireEncryptedMessage(SessionID sessionID,
			String msgText) throws OtrException;

	public abstract OtrPolicy getSessionPolicy(SessionID sessionID);

	public abstract KeyPair getLocalKeyPair(SessionID sessionID)
			throws OtrException;

	public abstract byte[] getLocalFingerprintRaw(SessionID sessionID);

	public abstract void askForSecret(SessionID sessionID, String question);

	public abstract void verify(SessionID sessionID, boolean approved);

	public abstract void unverify(SessionID sessionID);

	public abstract String getReplyForUnreadableMessage(SessionID sessionID);

	public abstract String getFallbackMessage(SessionID sessionID);
}
