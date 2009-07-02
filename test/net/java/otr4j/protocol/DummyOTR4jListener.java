package net.java.otr4j.protocol;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.logging.*;

import net.java.otr4j.OTR4jListener;
import net.java.otr4j.context.ConnContext;
import net.java.otr4j.crypto.CryptoUtils;

public class DummyOTR4jListener implements OTR4jListener {

	public DummyOTR4jListener(int policy) {
		this.policy = policy;
	}

	private static Logger logger = Logger.getLogger(DummyOTR4jListener.class.getName());
	private int policy;
	public String lastInjectedMessage;

	@Override
	public int getPolicy(ConnContext ctx) {
		return this.policy;
	}

	@Override
	public void injectMessage(String msg) {

		this.lastInjectedMessage = msg;
		String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10) + "..."
				: msg;
		logger.info("IM injects message: " + msgDisplay);
	}

	@Override
	public void showError(String error) {
		logger.severe("IM shows error to user: " + error);
	}

	@Override
	public void showWarning(String warning) {
		logger.warning("IM shows warning to user: " + warning);
	}

	@Override
	public KeyPair getKeyPair(String account, String protocol)
			throws NoSuchAlgorithmException {
		logger.info("IM generates a DSA key pair.");
		return CryptoUtils.generateDsaKeyPair();
	}

}
