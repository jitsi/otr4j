package net.java.otr4j.protocol;

public class PolicyUtils {
	public static Boolean getAllowV1(int policy) {
		return (policy & Policy.ALLOW_V1) != 0;
	}

	public static Boolean getAllowV2(int policy) {
		return (policy & Policy.ALLOW_V2) != 0;
	}

	public static Boolean getRequireEncryption(int policy) {
		return (policy & Policy.REQUIRE_ENCRYPTION) != 0;
	}

	public static Boolean getWhiteSpaceStartsAKE(int policy) {
		return (policy & Policy.WHITESPACE_START_AKE) != 0;
	}

	public static Boolean getErrorStartsAKE(int policy) {
		return (policy & Policy.ERROR_START_AKE) != 0;
	}
}
