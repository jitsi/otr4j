package net.java.otr4j;

import net.java.otr4j.session.SessionStatus;

/**
 * 
 * @author george
 * 
 * @param <T>
 *            A class that identifies the Session.
 */
public interface OtrEngine<T> {

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @return The transformed message content.
	 * @throws OtrException
	 */
	public String transformReceived(T sessionID, String content)
			throws OtrException;

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @return The transformed message content.
	 * @throws OtrException
	 */
	public String transformSending(T sessionID, String content)
			throws OtrException;

	/**
	 * Starts an Off-the-Record session, if there is no active one.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException
	 */
	public void startSession(T sessionID) throws OtrException;

	/**
	 * Ends the Off-the-Record session, if exists.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException
	 */
	public void endSession(T sessionID) throws OtrException;

	/**
	 * Stops/Starts the Off-the-Record session.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException
	 */
	public void refreshSession(T sessionID) throws OtrException;

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @return The status of an Off-the-Record session.
	 */
	public SessionStatus getSessionStatus(T sessionID);
}
