package net.java.otr4j.protocol;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public interface OTR4jListener {
	public void injectMessage(String msg);

	public void showWarning(String warning);

	public void showError(String error);

	public int getPolicy(ConnContext ctx);

	public KeyPair createPrivateKey(String account, String protocol)
			throws NoSuchAlgorithmException;
}
