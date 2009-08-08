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
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionImpl;
import net.java.otr4j.session.SessionStatus;

/**
 * 
 * @author George Politis
 * 
 */
public class OtrEngineImpl implements OtrEngine<SessionID> {

	public OtrEngineImpl(OtrEngineListener listener) {
		this.setListener(listener);
	}

	private OtrEngineListener listener;
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

	public String transformReceiving(SessionID sessionID, String msgText) {
		try {
			return this.getSession(sessionID).transformReceiving(msgText);
		} catch (OtrException e) {
			listener.showError(sessionID, e.getMessage());
			return null;
		}
	}

	public String transformSending(SessionID sessionID, String msgText) {
		try {
			return this.getSession(sessionID).transformSending(msgText, null);
		} catch (OtrException e) {
			listener.showError(sessionID, e.getMessage());
			return null;
		}
	}

	public void endSession(SessionID sessionID) {
		try {
			this.getSession(sessionID).endSession();
		} catch (OtrException e) {
			listener.showError(sessionID, e.getMessage());
		}
	}

	public void startSession(SessionID sessionID) {
		try {
			this.getSession(sessionID).startSession();
		} catch (OtrException e) {
			listener.showError(sessionID, e.getMessage());
		}
	}

	private void setListener(OtrEngineListener listener) {
		this.listener = listener;
	}

	private OtrEngineListener getListener() {
		return listener;
	}

	public void refreshSession(SessionID sessionID) {
		try {
			this.getSession(sessionID).refreshSession();
		} catch (OtrException e) {
			listener.showError(sessionID, e.getMessage());
		}
	}
}
