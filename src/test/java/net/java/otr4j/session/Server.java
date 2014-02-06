package net.java.otr4j.session;

import net.java.otr4j.OtrException;

/**
 * Created by gp on 2/6/14.
 */
public interface Server {
	void send(Connection sender, String recipient, String msg) throws OtrException;

	Connection connect(DummyClient client);
}
