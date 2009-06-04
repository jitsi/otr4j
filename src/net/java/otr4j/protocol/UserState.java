package net.java.otr4j.protocol;

import java.security.KeyPair;
import java.util.Hashtable;
import javax.crypto.interfaces.DHPublicKey;

public final class UserState {
	MessageState messageState;
	AuthenticationState authenticationState;

	private Hashtable<Integer, KeyPair> our_dh;
	private Hashtable<Integer, DHPublicKey> their_y;

	public Hashtable<Integer, KeyPair> getOur_dh() {
		if (our_dh == null)
			our_dh = new Hashtable<Integer, KeyPair>();
		return our_dh;
	}

	public Hashtable<Integer, DHPublicKey> getTheir_y() {
		if (their_y == null)
			their_y = new Hashtable<Integer, DHPublicKey>();

		return their_y;
	}

	private int policy;
	public Boolean getAllowV1() {
		return (this.policy & Policy.ALLOW_V1) != 0;
	}

	public Boolean getAllowV2() {
		return (this.policy & Policy.ALLOW_V2) != 0;
	}

	public Boolean getRequireEncryption() {
		return (this.policy & Policy.REQUIRE_ENCRYPTION) != 0;
	}
	
	public Boolean getWhiteSpaceStartsAKE(){
		return (this.policy & Policy.WHITESPACE_START_AKE) != 0;
	}
	
	public Boolean getErrorStartsAKE(){
		return (this.policy & Policy.ERROR_START_AKE) != 0;
	}
}
