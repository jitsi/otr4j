package net.java.otr4j.session;

import net.java.otr4j.OtrException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by gp on 2/5/14.
 */
public class PriorityServer implements Server {

	private final Map<String, PriorityConnection> clients = new HashMap<String, PriorityConnection>();
	private String lastMessage;

	public void send(PriorityConnection sender, String recipient, String msg) throws OtrException {

		// Update the active sender connection.
		clients.put(sender.getClient().getAccount(), sender);

		// Dispatch the message.
		PriorityConnection recipientConnection = clients.get(recipient);
		recipientConnection.receive(sender.getClient().getAccount(), msg);

		this.lastMessage = msg;
	}

	public String getLastMessage() {
		return lastMessage;
	}

	private int conCount;

	public PriorityConnection connect(DummyClient client) {

		String connectionName = client.getAccount() + "." + conCount++;
		PriorityConnection con = new PriorityConnection(client, connectionName);

		// Update the active connection.
		clients.put(client.getAccount(), con);

		// Return the connection object to the client.
		return con;
	}

	class PriorityConnection implements Connection {


		private final DummyClient client;
		private final String connectionName;

		public PriorityConnection(DummyClient client, String connectionName) {
			this.client = client;
			this.connectionName = connectionName;
		}

		public DummyClient getClient() {
			return client;
		}

		@Override
		public String toString() {
			return "PriorityConnection{" +
					"connectionName='" + connectionName + '\'' +
					'}';
		}

		public void send(String recipient, String msg) throws OtrException {
			PriorityServer.this.send(this, recipient, msg);
		}

		public void receive(String sender, String msg) throws OtrException {
			this.client.receive(sender, msg);
		}


	}
}
