package net.java.otr4j.context;

import java.security.KeyPair;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.context.auth.AuthenticationInfo;

/**
 *
 * @author george
 */
public class ConnContext {
	public String user;
	public String account;
	public String protocol;
	public MessageState messageState;
	
    public AuthenticationInfo authenticationInfo;
    
    public int localPreviousKeyID;
    public KeyPair localPreviousKeyPair;
    
    public int localCurrentKeyID;
    public KeyPair localCurrentKeyPair;
    
    public int remotePreviousKeyID;
    public DHPublicKey remotePreviousDHublicKey;
    
    public int remoteCurrentKeyID;
    public DHPublicKey remoteCurrentDHPublicKey;
    
    public String lastSentMessage;
    
    public ConnContext(String user, String account, String protocol){
        this.user = user;
        this.account = account;
        this.protocol = protocol;
        this.messageState = MessageState.PLAINTEXT;
        this.authenticationInfo = new AuthenticationInfo();
    }
}
