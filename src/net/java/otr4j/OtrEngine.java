package net.java.otr4j;

import java.security.PublicKey;

import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;

/**
 * 
 * @author George Politis
 * 
 */
public interface OtrEngine {

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @return The transformed message content.
	 */
	public abstract String transformReceiving(SessionID sessionID,
			String content);

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @return The transformed message content.
	 */
	public abstract String transformSending(SessionID sessionID, String content);

	/**
	 * Starts an Off-the-Record session, if there is no active one.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 */
	public abstract void startSession(SessionID sessionID);

	/**
	 * Ends the Off-the-Record session, if exists.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 */
	public abstract void endSession(SessionID sessionID);

	/**
	 * Stops/Starts the Off-the-Record session.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 */
	public abstract void refreshSession(SessionID sessionID);

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @return The status of an Off-the-Record session.
	 */
	public abstract SessionStatus getSessionStatus(SessionID sessionID);

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @return The remote public key.
	 */
	public abstract PublicKey getRemotePublicKey(SessionID sessionID);

	public abstract void addOtrEngineListener(OtrEngineListener l);

	public abstract void removeOtrEngineListener(OtrEngineListener l);
}
