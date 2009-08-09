package net.java.otr4j;

import net.java.otr4j.session.SessionStatus;

/**
 * 
 * @author George Politis
 * 
 * @param <T>
 *            A class that identifies the Session.
 */
public interface OtrEngine<T, Z> {

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @return The transformed message content.
	 * @throws OtrException
	 */
	public String transformReceiving(T sessionID, String content);

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @return The transformed message content.
	 * @throws OtrException
	 */
	public String transformSending(T sessionID, String content);

	/**
	 * Starts an Off-the-Record session, if there is no active one.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException
	 */
	public void startSession(T sessionID);

	/**
	 * Ends the Off-the-Record session, if exists.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException
	 */
	public void endSession(T sessionID);

	/**
	 * Stops/Starts the Off-the-Record session.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException
	 */
	public void refreshSession(T sessionID);

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @return The status of an Off-the-Record session.
	 */
	public SessionStatus getSessionStatus(T sessionID);
	
	public boolean getSessionIsAuthenticated(T sessionID);
	
	public String getSessionFingerprint(T sessionID);
	
	public Z getSessionID(T sessionID);
}
