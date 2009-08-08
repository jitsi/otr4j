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
import net.java.otr4j.session.SessionIDImpl;
import net.java.otr4j.session.SessionStatus;

/**
 * 
 * @author George Politis
 * 
 */
public class OtrEngineImpl implements OtrEngine<SessionIDImpl> {

	public OtrEngineImpl(OtrEngineListener<SessionIDImpl> listener) {
		this.setListener(listener);
	}

	private OtrEngineListener<SessionIDImpl> listener;
	private Map<SessionIDImpl, Session> sessions;

	private Session getSession(SessionIDImpl sessionID) {

		if (sessionID == null || sessionID.equals(SessionIDImpl.Empty))
			throw new IllegalArgumentException();

		if (sessions == null)
			sessions = new Hashtable<SessionIDImpl, Session>();

		if (!sessions.containsKey(sessionID))
			sessions.put(sessionID, new SessionImpl(sessionID, getListener()));

		return sessions.get(sessionID);
	}

	public SessionStatus getSessionStatus(SessionIDImpl sessionID) {
		return this.getSession(sessionID).getSessionStatus();
	}

	public String transformReceived(SessionIDImpl sessionID, String msgText)
			throws OtrException {
		return this.getSession(sessionID).transformReceiving(msgText);
	}

	public String transformSending(SessionIDImpl sessionID, String msgText)
			throws OtrException {
		return this.getSession(sessionID).transformSending(msgText, null);
	}

	public void endSession(SessionIDImpl sessionID) throws OtrException {
		this.getSession(sessionID).endSession();
	}

	public void startSession(SessionIDImpl sessionID) throws OtrException {
		this.getSession(sessionID).startSession();
	}

	private void setListener(OtrEngineListener<SessionIDImpl> listener) {
		this.listener = listener;
	}

	private OtrEngineListener<SessionIDImpl> getListener() {
		return listener;
	}

	public void refreshSession(SessionIDImpl sessionID) throws OtrException {
		this.getSession(sessionID).refreshSession();
	}
}
