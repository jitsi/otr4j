package net.java.otr4j;

@SuppressWarnings("serial")
public class OtrException extends Exception {

	public OtrException(String msg) {
		super(msg);
	}

	public OtrException(String msg, Exception innerException) {
		super(msg, innerException);
	}

	public OtrException(Exception innerException) {
		super(innerException);
	}
}
