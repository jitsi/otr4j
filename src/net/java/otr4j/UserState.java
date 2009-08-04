/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;

/**
 * 
 * @author George Politis
 * 
 */
public class UserState implements OtrEngine<SessionID> {
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

	public int getSessionStatus(SessionID sessionID) {
		Session session = getSession(sessionID);
		return session.getSessionStatus();
	}

	public String handleReceivingMessage(SessionID sessionID, String msgText) {

		try {
			return this.getSession(sessionID).handleReceivingMessage(msgText);
		} catch (Exception e) {
			logger
					.log(
							Level.SEVERE,
							"Handling message receiving failed, returning original message.",
							e);
			getListener().showError(sessionID, "Handling message receiving failed.");
			return null;
		}
	}

	public String handleSendingMessage(SessionID sessionID, String msgText) {

		try {
			return this.getSession(sessionID).handleSendingMessage(msgText,
					null);
		} catch (Exception e) {
			logger
					.log(
							Level.SEVERE,
							"Handling message sending failed, returning original message.",
							e);
			getListener().showError(sessionID, "Handling message sending failed.");
			return null;
		}
	}

	@Override
	public void endSession(SessionID sessionID) {
		try {
			this.getSession(sessionID).endSession();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OtrException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void startSession(SessionID sessionID) {
		try {
			this.getSession(sessionID).startSession();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OtrException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void setListener(OTR4jListener listener) {
		this.listener = listener;
	}

	private OTR4jListener getListener() {
		return listener;
	}

	@Override
	public void refreshSession(SessionID sessionID) {
		try {
			this.getSession(sessionID).refreshSession();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OtrException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
