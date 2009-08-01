/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 
 * @author George Politis
 * 
 */
public final class UserState {
	public UserState(OTR4jListener listener) {
		this.setListener(listener);
	}

	private OTR4jListener listener;
	private Map<SessionID, Session> sessions = new Hashtable<SessionID, Session>();
	private static Logger logger = Logger.getLogger(Session.class.getName());

	private Session getSession(SessionID sessionID) {

		if (sessionID == null)
			throw new IllegalArgumentException();

		if (!sessions.containsKey(sessionID))
			sessions.put(sessionID, new Session(sessionID, getListener()));

		return sessions.get(sessionID);
	}

	public SessionStatus getSessionStatus(SessionID sessionID) {
		Session context = getSession(sessionID);
		SessionStatus status = new SessionStatus(context.getMessageState());
		return status;
	}

	public String handleReceivingMessage(SessionID sessionID, String msgText) {

		try {
			return this.getSession(sessionID).handleReceivingMessage(
					msgText);
		} catch (Exception e) {
			logger
					.log(
							Level.SEVERE,
							"Handling message receiving failed, returning original message.",
							e);
			getListener().showError("Handling message receiving failed.");
			return null;
		}
	}

	public String handleSendingMessage(SessionID sessionID, String msgText) {

		try {
			return this.getSession(sessionID).handleSendingMessage(msgText);
		} catch (Exception e) {
			logger
					.log(
							Level.SEVERE,
							"Handling message sending failed, returning original message.",
							e);
			getListener().showError("Handling message sending failed.");
			return null;
		}
	}

	private void setListener(OTR4jListener listener) {
		this.listener = listener;
	}

	public OTR4jListener getListener() {
		return listener;
	}
}
