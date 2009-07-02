package net.java.otr4j;

import java.security.*;

import net.java.otr4j.context.*;

public interface OTR4jListener {
	public void injectMessage(String msg);

	public void showWarning(String warning);

	public void showError(String error);
	
	public int getPolicy(ConnContext ctx);

	public KeyPair getKeyPair(String account, String protocol)
			throws NoSuchAlgorithmException;
}
