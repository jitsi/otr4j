/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.Hashtable;
import java.util.Map;

import net.java.otr4j.session.ISession;
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
	private Map<SessionID, SessionImpl> sessions;

	private ISession getSession(SessionID sessionID) {

		if (sessionID == null || sessionID.equals(SessionID.Empty))
			throw new IllegalArgumentException();

		if (sessions == null)
			sessions = new Hashtable<SessionID, SessionImpl>();

		if (!sessions.containsKey(sessionID))
			sessions.put(sessionID, new SessionImpl(sessionID, getListener()));

		return sessions.get(sessionID);
	}

	public SessionStatus getSessionStatus(SessionID sessionID) {
		ISession session = getSession(sessionID);
		return session.getSessionStatus();
	}

	public String transformReceived(SessionID sessionID, String msgText)
			throws OtrException {

		try {
			return this.getSession(sessionID).handleReceivingMessage(msgText);
		} catch (Exception e) {
			throw new OtrException(e);
		}
	}

	public String transformSending(SessionID sessionID, String msgText)
			throws OtrException {
		try {
			return this.getSession(sessionID).handleSendingMessage(msgText,
					null);
		} catch (Exception e) {
			throw new OtrException(e);
		}
	}

	public void endSession(SessionID sessionID) throws OtrException {
		try {
			this.getSession(sessionID).endSession();
		} catch (Exception e) {
			throw new OtrException(e);
		}
	}

	public void startSession(SessionID sessionID) throws OtrException {
		try {
			this.getSession(sessionID).startSession();
		} catch (Exception e) {
			throw new OtrException(e);
		}
	}

	private void setListener(OtrEngineListener<SessionID> listener) {
		this.listener = listener;
	}

	private OtrEngineListener<SessionID> getListener() {
		return listener;
	}

	public void refreshSession(SessionID sessionID) throws OtrException {
		try {
			this.getSession(sessionID).refreshSession();
		} catch (Exception e) {
			throw new OtrException(e);
		}
	}
}
