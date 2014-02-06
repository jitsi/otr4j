package net.java.otr4j.session;

import net.java.otr4j.OtrException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by gp on 2/5/14.
 */
public class PriorityServer implements Server {

	private final Map<String, Connection> clients = new HashMap<String, Connection>();
	private int conCount;

	public void send(Connection sender, String recipient, String msg) throws OtrException {

		// Update the active sender connection.
		clients.put(sender.getClient().getAccount(), sender);

		// Dispatch the message.
		Connection recipientConnection = clients.get(recipient);
		recipientConnection.receive(sender.getClient().getAccount(), msg);
	}

	public synchronized Connection connect(DummyClient client) {

		String connectionName = client.getAccount() + "." + conCount++;
		Connection con = new Connection(this, client, connectionName);

		// Update the active connection.
		clients.put(client.getAccount(), con);

		// Return the connection object to the client.
		return con;
	}
}
