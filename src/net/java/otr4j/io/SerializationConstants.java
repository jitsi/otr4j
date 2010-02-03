/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

/**
 * 
 * @author George Politis
 */
public interface SerializationConstants {
	public static final byte[] HEAD = "?OTR".getBytes();
	public static final byte[] HEAD_ENCODED = ":".getBytes();
	public static final byte[] HEAD_ERROR = " ".getBytes();
	public static final byte[] HEAD_QUERY_Q = "?".getBytes();
	public static final byte[] HEAD_QUERY_V = "v".getBytes();

	public static final int TYPE_LEN_BYTE = 1;
	public static final int TYPE_LEN_SHORT = 2;
	public static final int TYPE_LEN_INT = 4;
	public static final int TYPE_LEN_MAC = 20;
	public static final int TYPE_LEN_CTR = 8;

	public static final int DATA_LEN = TYPE_LEN_INT;
	public static final int TLV_LEN = TYPE_LEN_SHORT;
}
