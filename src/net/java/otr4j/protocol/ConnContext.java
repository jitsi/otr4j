/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.java.otr4j.protocol;

import java.util.LinkedList;

import net.java.otr4j.protocol.crypto.DHPublicKeyContainer;
import net.java.otr4j.protocol.crypto.DHKeyPairContainer;

/**
 *
 * @author george
 */
public class ConnContext {
	public String user;
	public String account;
	public String protocol;
	public MessageState messageState;
	
    public AuthenticationState authenticationState;
    
    public LinkedList<DHKeyPairContainer> our_dh;
    public LinkedList<DHPublicKeyContainer> their_y;
    public byte[] r;
    
    public ConnContext(String user, String account, String protocol){
        this.user = user;
        this.account = account;
        this.protocol = protocol;
        this.messageState = MessageState.PLAINTEXT;
        this.authenticationState = AuthenticationState.NONE;
    }
}
