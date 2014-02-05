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
public interface OtrSessionManager {

	/** Get an OTR session. */
	public abstract Session getSession(SessionID sessionID);

	public abstract void addOtrEngineListener(OtrEngineListener l);

	public abstract void removeOtrEngineListener(OtrEngineListener l);
}
