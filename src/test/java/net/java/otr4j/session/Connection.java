package net.java.otr4j.session;

import net.java.otr4j.OtrException;

/**
 * Created by gp on 2/6/14.
 */
interface Connection {

	public void send(String recipient, String msg) throws OtrException;

	public void receive(String sender, String msg) throws OtrException;

}