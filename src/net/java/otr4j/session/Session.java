package net.java.otr4j.session;

import java.util.List;

import net.java.otr4j.OtrException;
import net.java.otr4j.session.SessionImpl.TLV;

public interface Session {

	public abstract SessionStatus getSessionStatus();

	public abstract SessionIDImpl getSessionID();

	public abstract String transformReceiving(String content)
			throws OtrException;

	public abstract String transformSending(String content, List<TLV> tlvs)
			throws OtrException;

	public abstract void startSession() throws OtrException;

	public abstract void endSession() throws OtrException;

	public abstract void refreshSession() throws OtrException;

}