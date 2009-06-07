/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.java.otr4j.protocol;

import java.security.KeyPair;
import java.util.Hashtable;
import javax.crypto.interfaces.DHPublicKey;

/**
 *
 * @author george
 */
public class ConnContext {
    private String user;
    private String account;
    private String protocol;
    
    public ConnContext(String user, String account, String protocol){
        this.user = user;
        this.account = account;
        this.protocol = protocol;
        this.messageState = MessageState.PLAINTEXT;
    }

    MessageState messageState;
    AuthenticationState authenticationState;
    private Hashtable<Integer, KeyPair> our_dh;
    private Hashtable<Integer, DHPublicKey> their_y;

    public Hashtable<Integer, KeyPair> getOur_dh() {
        if (our_dh == null) {
            our_dh = new Hashtable<Integer, KeyPair>();
        }
        return our_dh;
    }

    public Hashtable<Integer, DHPublicKey> getTheir_y() {
        if (their_y == null) {
            their_y = new Hashtable<Integer, DHPublicKey>();
        }

        return their_y;
    }

    /**
     * @return the user
     */
    public String getUser() {
        return user;
    }

    /**
     * @return the account
     */
    public String getAccount() {
        return account;
    }

    /**
     * @return the protocol
     */
    public String getProtocol() {
        return protocol;
    }
}
