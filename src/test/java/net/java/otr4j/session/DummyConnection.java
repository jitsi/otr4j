package net.java.otr4j.session;

import net.java.otr4j.OtrException;

/**
 * Created by gp on 2/6/14.
 */
class DummyConnection {


	public DummyConnection(String sender, DummyServer server){
		this.sender = sender;
		this.server = server;
	}
	private final String sender;
	private final DummyServer server;

	public void send(String recipient, String msg) throws OtrException {
		server.send(sender, recipient, msg);
	}
}