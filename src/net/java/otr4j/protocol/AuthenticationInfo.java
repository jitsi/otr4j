package net.java.otr4j.protocol;

import java.security.KeyPair;

import javax.crypto.interfaces.DHPublicKey;

public class AuthenticationInfo {

	public AuthenticationInfo(){
		this.authenticationState = AuthenticationState.NONE;
	}
	
	public AuthenticationState authenticationState;
	public byte[] r;
	public byte[] their_yEncrypted;
    public byte[] their_yHash;
    public KeyPair our_dh;
    public int our_keyid;
    public DHPublicKey their_pub;
    public byte[] hashgx;
}
