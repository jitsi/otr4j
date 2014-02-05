package net.java.otr4j.session;

import net.java.otr4j.OtrException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by gp on 2/5/14.
 */
public class DummyServer {

	private final Map<String, DummyClient> clients = new HashMap<String, DummyClient>();

	public void send(String sender, String recipient, String msg) throws OtrException {
		DummyClient recipientClient = clients.get(recipient);
		recipientClient.accept(sender, msg);
		this.lastMessage = msg;
	}

	private String lastMessage;
	public String getLastMesasge(){
		return lastMessage;
	}

	public DummyConnection connect(String account, DummyClient dummyClient) {
		clients.put(account, dummyClient);
		return new DummyConnection(account, this);
	}
}
