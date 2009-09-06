package net.java.otr4j;

import net.java.otr4j.session.SessionID;

public interface OtrEngineListener {
	public abstract void sessionStatusChanged(SessionID sessionID);
}
