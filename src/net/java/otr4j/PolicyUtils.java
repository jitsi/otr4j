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
public class PolicyUtils implements PolicyConstants {
	public static Boolean getAllowV1(int policy) {
		return (policy & ALLOW_V1) != 0;
	}

	public static Boolean getAllowV2(int policy) {
		return (policy & ALLOW_V2) != 0;
	}

	public static Boolean getRequireEncryption(int policy) {
		return (policy & REQUIRE_ENCRYPTION) != 0;
	}

	public static Boolean getWhiteSpaceStartsAKE(int policy) {
		return (policy & WHITESPACE_START_AKE) != 0;
	}

	public static Boolean getErrorStartsAKE(int policy) {
		return (policy & ERROR_START_AKE) != 0;
	}
}
