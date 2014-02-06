package net.java.otr4j.session;

import net.java.otr4j.OtrException;

/**
 * Created by gp on 2/6/14.
 */
public interface Server {
	void send(PriorityServer.PriorityConnection sender, String recipient, String msg) throws OtrException;

	String getLastMessage();

	PriorityServer.PriorityConnection connect(DummyClient client);
}
