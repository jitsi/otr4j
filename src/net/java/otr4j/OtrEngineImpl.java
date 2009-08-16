/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.security.PublicKey;
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
public class OtrEngineImpl implements OtrEngine {

	public OtrEngineImpl(OtrEngineHost listener) {
		this.setListener(listener);
	}

	private OtrEngineHost listener;
	private Map<SessionID, Session> sessions;

	private Session getSession(SessionID sessionID) {

		if (sessionID == null || sessionID.equals(SessionID.Empty))
			throw new IllegalArgumentException();

		if (sessions == null)
			sessions = new Hashtable<SessionID, Session>();

		if (!sessions.containsKey(sessionID)) {
			Session session = new SessionImpl(sessionID, getListener());
			sessions.put(sessionID, session);

		}

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

	private void setListener(OtrEngineHost listener) {
		this.listener = listener;
	}

	private OtrEngineHost getListener() {
		return listener;
	}

	public void refreshSession(SessionID sessionID) {
		try {
			this.getSession(sessionID).refreshSession();
		} catch (OtrException e) {
			listener.showError(sessionID, e.getMessage());
		}
	}

	public PublicKey getRemotePublicKey(SessionID sessionID) {
		return this.getSession(sessionID).getRemotePublicKey();
	}
}
