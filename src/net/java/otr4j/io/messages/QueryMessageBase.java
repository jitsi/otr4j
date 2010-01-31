package net.java.otr4j.io.messages;

import java.util.Vector;



public abstract class QueryMessageBase extends MessageBase {
	private Vector<Integer> versions;
	
	public QueryMessageBase(int messageType){
		super(messageType);
	}

	public void setVersions(Vector<Integer> versions) {
		this.versions = versions;
	}

	public Vector<Integer> getVersions() {
		return versions;
	}
}
