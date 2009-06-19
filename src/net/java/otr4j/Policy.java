package net.java.otr4j;

/**
 * OTR clients can set different policies for different correspondents. For
 * example, Alice could set up her client so that it speaks only OTR version 2,
 * except with Charlie, who she knows has only an old client; so that it will
 * opportunistically start an OTR conversation whenever it detects the
 * correspondent supports it; or so that it refuses to send non-encrypted
 * messages to Bob, ever.
 * 
 * @author george
 * 
 */
public interface Policy {
	// The policies that can be set (on a global or per-correspondent basis) are any combination of the following boolean flags:
	
	/**
	 * Allow version 1 of the OTR protocol to be used.
	 */
	public static final int ALLOW_V1 = 0x01;
	/**
	 * Allow version 2 of the OTR protocol to be used.
	 */
	public static final int ALLOW_V2 = 0x02;
	/**
	 * Refuse to send unencrypted messages.
	 */
	public static final int REQUIRE_ENCRYPTION = 0x04;
	/**
	 * Advertise your support of OTR using the whitespace tag.
	 */
	public static final int SEND_WHITESPACE_TAG = 0x08;
	/**
	 * Start the OTR AKE when you receive a whitespace tag.
	 */
	public static final int WHITESPACE_START_AKE = 0x10;
	/**
	 * Start the OTR AKE when you receive an OTR Error Message.
	 */
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
