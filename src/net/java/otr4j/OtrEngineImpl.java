/*
 * otr4j, the open source java otr librar
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.security.PublicKey;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Vector;

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

	public OtrEngineImpl(OtrEngineHost listener, OtrKeyManager keyManager) {
		this.setListener(listener);
		this.setKeyManager(keyManager);
	}

	private OtrEngineHost listener;
	private OtrKeyManager keyManager;
	private Map<SessionID, Session> sessions;

	private Session getSession(SessionID sessionID) {

		if (sessionID == null || sessionID.equals(SessionID.Empty))
			throw new IllegalArgumentException();

		if (sessions == null)
			sessions = new Hashtable<SessionID, Session>();

		if (!sessions.containsKey(sessionID)) {
			Session session = new SessionImpl(sessionID, getListener(),
					getKeyManager());
			sessions.put(sessionID, session);

			session.addOtrEngineListener(new OtrEngineListener() {

				public void sessionStatusChanged(SessionID sessionID) {
					for (OtrEngineListener l : listeners)
						l.sessionStatusChanged(sessionID);
				}
			});

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

	private void setKeyManager(OtrKeyManager keyManager) {
		this.keyManager = keyManager;
	}

	private OtrKeyManager getKeyManager() {
		return keyManager;
	}

	private List<OtrEngineListener> listeners = new Vector<OtrEngineListener>();

	public void addOtrEngineListener(OtrEngineListener l) {
		synchronized (listeners) {
			if (!listeners.contains(l))
				listeners.add(l);
		}

	}

	public void removeOtrEngineListener(OtrEngineListener l) {
		synchronized (listeners) {
			listeners.remove(l);
		}
	}
}
