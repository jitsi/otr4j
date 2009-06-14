package net.java.otr4j.protocol;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;

import net.java.otr4j.protocol.crypto.CryptoUtils;

public class DummyOTR4jListener implements OTR4jListener {
	
	public DummyOTR4jListener(int policy){
		this.policy = policy;
	}
	
	private static Logger logger = Logger.getLogger(DummyOTR4jListener.class);
	private int policy;
	
	@Override
	public int getPolicy(ConnContext ctx) {
		return this.policy;
	}

	@Override
	public void injectMessage(String msg) {
		String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10) + "..." : msg;
		logger.debug("Dummy message injection: " + msgDisplay);
	}

	@Override
	public void showError(String error) {
		logger.debug("Dummy error display: " + error);
	}

	@Override
	public void showWarning(String warning) {
		logger.debug("Dummy warning display: " + warning);
	}

	@Override
	public KeyPair createPrivateKey(String account, String protocol)
			throws NoSuchAlgorithmException {
		return CryptoUtils.generateDsaKeyPair();
	}

}
