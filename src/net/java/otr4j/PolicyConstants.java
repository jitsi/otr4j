/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

/**
 * 
 * @author George Politis
 *
 */
public interface PolicyConstants {
	
	public static final int ALLOW_V1 = 0x01;	
	public static final int ALLOW_V2 = 0x02;
	public static final int REQUIRE_ENCRYPTION = 0x04;
	public static final int SEND_WHITESPACE_TAG = 0x08;
	public static final int WHITESPACE_START_AKE = 0x10;
	public static final int ERROR_START_AKE = 0x20;
	public static final int VERSION_MASK = (ALLOW_V1 | ALLOW_V2);

	// The four old version 1 policies correspond to the following combinations of flags (adding an allowance for version 2 of the protocol):
	
	public static final int NEVER = 0x00;
	public static final int OPPORTUNISTIC = (ALLOW_V1 | ALLOW_V2
			| SEND_WHITESPACE_TAG | WHITESPACE_START_AKE | ERROR_START_AKE);
	public static final int OTRL_POLICY_MANUAL = (ALLOW_V1 | ALLOW_V2);
	public static final int OTRL_POLICY_ALWAYS = (ALLOW_V1 | ALLOW_V2
			| REQUIRE_ENCRYPTION | WHITESPACE_START_AKE | ERROR_START_AKE);
	public static final int OTRL_POLICY_DEFAULT = OPPORTUNISTIC;
}
