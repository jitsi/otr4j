/*
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.java.otr4j.session;

import net.java.otr4j.OtrException;

import java.util.HashMap;
import java.util.Map;

/**
 * @author George Politis
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
