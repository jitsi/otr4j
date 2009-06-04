package net.java.otr4j.protocol;

public interface OTR4jListener {
	public void injectMessage(String msg);
	public void showWarning(String warning);
	public void showError(String error);
}
