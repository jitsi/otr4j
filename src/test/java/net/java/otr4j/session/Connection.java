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

/**
 * @author George Politis
 */
class Connection {

	private final DummyClient client;
	private final String connectionName;
	private final Server server;

	public String getSentMessage() {
		return sentMessage;
	}

	private String sentMessage;

	public Connection(Server server, DummyClient client, String connectionName) {
		this.client = client;
		this.server = server;
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
		this.sentMessage = msg;
		server.send(this, recipient, msg);
	}

	public void receive(String sender, String msg) throws OtrException {
		this.client.receive(sender, msg);
	}
}