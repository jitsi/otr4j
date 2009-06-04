package net.java.otr4j.message;

public interface MessageHeader {
	public static final String BASE = "?OTR";
	public static final String ENCODED_MESSAGE = "?OTR:";
	public static final String DH_COMMIT = "?OTR:AAIC";
	public static final String DH_KEY = "?OTR:AAIK";
	public static final String REVEALSIG = "?OTR:AAIR";
	public static final String SIGNATURE = "?OTR:AAIS";
	public static final String ERROR = "?OTR Error:";
	public static final String QUERY1 = "?OTR?";
	public static final String QUERY2 = "?OTRv";
	public static final String DATA1 = "?OTR:AAED";
	public static final String DATA2 = "?OTR:AAID";
	public static final String V1_KEY_EXCHANGE = "?OTR:AAEK";
}
