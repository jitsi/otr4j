/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.Hashtable;
import java.util.Map;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionImpl;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;

/**
 * 
 * @author George Politis
 * 
 */
public class OtrEngineImpl implements OtrEngine<SessionID> {

	public OtrEngineImpl(OtrEngineListener<SessionID> listener) {
		this.setListener(listener);
	}

	private OtrEngineListener<SessionID> listener;
	private Map<SessionID, Session> sessions;

	private Session getSession(SessionID sessionID) {

		if (sessionID == null || sessionID.equals(SessionID.Empty))
			throw new IllegalArgumentException();

		if (sessions == null)
			sessions = new Hashtable<SessionID, Session>();

		if (!sessions.containsKey(sessionID))
			sessions.put(sessionID, new SessionImpl(sessionID, getListener()));

		return sessions.get(sessionID);
	}

	public SessionStatus getSessionStatus(SessionID sessionID) {
		return this.getSession(sessionID).getSessionStatus();
	}

	public String transformReceived(SessionID sessionID, String msgText)
			throws OtrException {
		return this.getSession(sessionID).transformReceiving(msgText);
	}

	public String transformSending(SessionID sessionID, String msgText)
			throws OtrException {
		return this.getSession(sessionID).transformSending(msgText, null);
	}

	public void endSession(SessionID sessionID) throws OtrException {
		this.getSession(sessionID).endSession();
	}

	public void startSession(SessionID sessionID) throws OtrException {
		this.getSession(sessionID).startSession();
	}

	private void setListener(OtrEngineListener<SessionID> listener) {
		this.listener = listener;
	}

	private OtrEngineListener<SessionID> getListener() {
		return listener;
	}

	public void refreshSession(SessionID sessionID) throws OtrException {
		this.getSession(sessionID).refreshSession();
	}
}
