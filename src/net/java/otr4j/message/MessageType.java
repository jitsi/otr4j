package net.java.otr4j.message;

public interface MessageType {
	// Encoded Message Types
	public static final int DH_COMMIT = 0x02;
	public static final int DATA = 0x03;
	public static final int DH_KEY = 0x0a;
	public static final int REVEALSIG = 0x11;
	public static final int SIGNATURE = 0x12;
	
	// Unencoded
	public static final int ERROR = 0xff;
	public static final int QUERY = 0x100;
	public static final int PLAINTEXT = 0x102;
	public static final int UKNOWN = 0x110;
	
	// Legacy
	public static final int V1_KEY_EXCHANGE = 0x103;
}
