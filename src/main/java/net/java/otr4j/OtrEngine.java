package net.java.otr4j;

import java.security.PublicKey;
import java.util.List;

import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.TLV;

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
	 * @throws OtrException 
	 */
	public abstract String transformReceiving(SessionID sessionID,
			String content) throws OtrException;

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @return The transformed message content.
	 * @throws OtrException 
	 */
	public abstract String transformSending(SessionID sessionID, String content) throws OtrException;

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @param content
	 *            The message content to be transformed.
	 * @param tlvs The TLVs to attach.
	 * @return The transformed message content.
	 * @throws OtrException 
	 */
	public abstract String transformSending(SessionID sessionID, String content, List<TLV> tlvs) throws OtrException;

	/**
	 * Starts an Off-the-Record session, if there is no active one.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException 
	 */
	public abstract void startSession(SessionID sessionID) throws OtrException;

	/** Get an OTR session. */
	public abstract Session getSession(SessionID sessionID);

	/**
	 * Get all instances of an OTR session. If our buddy is logged in multiple times
	 * we will have multiple instances.
	 */
	public abstract List<Session> getSessionInstances(SessionID sessionID);
	
	/**
	 * Some IM networks always relay all messages to all sessions of a client who
	 * is logged in multiple times. OTR version 3 deals with this problem with
	 * introducing instance tags.
	 * <a href="https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html">
	 * https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html</a>
	 * <p>
	 * When the client wishes to start sending OTRv3 encrypted messages to a specific session
	 * of his buddy who is logged in multiple times, he can set the outgoing instance of his
	 * buddy by specifying his <tt>InstanceTag</tt>.
	 * 
	 * @param sessionID
	 * 			The session identifier.
	 * @param tag
	 * 			The <tt>InstanceTag</tt> of the Session to which we would like to start
	 * sending messages to.
	 * 
	 * @return <tt>true</tt> if a Session with <tt>InstanceTag</tt> tag exists and the
	 * operation was successful. <tt>false</tt> otherwise
	 */
	public abstract boolean setOutgoingInstance(SessionID sessionID, InstanceTag tag);

	/**
	 * Ends the Off-the-Record session, if exists.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException 
	 */
	public abstract void endSession(SessionID sessionID) throws OtrException;

	/**
	 * Stops/Starts the Off-the-Record session.
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @throws OtrException 
	 */
	public abstract void refreshSession(SessionID sessionID) throws OtrException;

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @return The status of an Off-the-Record session.
	 */
	public abstract SessionStatus getSessionStatus(SessionID sessionID);

	/**
	 * Gets the session status of the session with receiver instance tag set to <tt>tag</tt>.
	 * It could be a slave session as well as the master session.
	 * 
	 * @param sessionID
	 * 			  The session identifier.
	 * @param tag
	 * 		      The receiver instance tag of the session.
	 * @return The status of the Off-The-Record session with receiver instance tag set to <tt>tag</tt>.
	 */
	public abstract SessionStatus getSessionStatus(SessionID sessionID, InstanceTag tag);

	/**
	 * 
	 * @param sessionID
	 *            The session identifier.
	 * @return The remote public key.
	 */
	public abstract PublicKey getRemotePublicKey(SessionID sessionID);

	/**
	 * Gets the remote public key of the session with id <tt>sessionID</tt> and receiver
	 * instance tag set to <tt>tag</tt>.
	 * 
	 * @param sessionID
	 * 			   The session identifier.
	 * @param tag
	 * 			   The receiver instance tag.
	 * @return The remote public key of the session with id <tt>sessionID</tt> and receiver
	 * instance tag set to <tt>tag</tt>
	 */
	public abstract PublicKey getRemotePublicKey(SessionID sessionID, InstanceTag tag);

	public abstract void addOtrEngineListener(OtrEngineListener l);

	public abstract void removeOtrEngineListener(OtrEngineListener l);
}
