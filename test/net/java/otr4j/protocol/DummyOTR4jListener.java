package net.java.otr4j.protocol;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.logging.*;

import net.java.otr4j.CryptoUtils;
import net.java.otr4j.OtrEngineListener;
import net.java.otr4j.session.SessionIDImpl;

public class DummyOTR4jListener implements OtrEngineListener<SessionIDImpl> {

	public DummyOTR4jListener(int policy) {
		this.policy = policy;
	}

	private static Logger logger = Logger.getLogger(DummyOTR4jListener.class
			.getName());
	private int policy;
	public String lastInjectedMessage;

	@Override
	public int getPolicy(SessionIDImpl ctx) {
		return this.policy;
	}

	@Override
	public void injectMessage(SessionIDImpl sessionID, String msg) {

		this.lastInjectedMessage = msg;
		String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10) + "..."
				: msg;
		logger.info("IM injects message: " + msgDisplay);
	}

	@Override
	public void showError(SessionIDImpl sessionID, String error) {
		logger.severe("IM shows error to user: " + error);
	}

	@Override
	public void showWarning(SessionIDImpl sessionID, String warning) {
		logger.warning("IM shows warning to user: " + warning);
	}

	@Override
	public KeyPair getKeyPair(SessionIDImpl sessionID) {
		logger.info("IM generates a DSA key pair.");
		try {
			return CryptoUtils.generateDsaKeyPair();
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

}
