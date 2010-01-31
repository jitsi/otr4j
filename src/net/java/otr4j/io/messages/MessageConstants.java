/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

/**
 * 
 * @author George Politis
 */
public interface MessageConstants {
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
	
	public static final String BASE_HEAD = "?OTR";
	public static final String ENCODED_MESSAGE_HEAD = "?OTR:";
	public static final String DH_COMMIT_HEAD = "?OTR:AAIC";
	public static final String DH_KEY_HEAD = "?OTR:AAIK";
	public static final String REVEALSIG_HEAD = "?OTR:AAIR";
	public static final String SIGNATURE_HEAD = "?OTR:AAIS";
	public static final String ERROR_HEAD = "?OTR Error:";
	public static final String QUERY1_HEAD = "?OTR?";
	public static final String QUERY2_HEAD = "?OTRv";
	public static final String DATA1_HEAD = "?OTR:AAED";
	public static final String DATA2_HEAD = "?OTR:AAID";
	public static final String V1_KEY_EXCHANGE_HEAD = "?OTR:AAEK";
	public static final CharSequence BASE = " \t  \t\t\t\t \t \t \t  ";
	public static final CharSequence V2 = "  \t\t  \t ";
	public static final CharSequence V1 = " \t \t  \t ";
}
