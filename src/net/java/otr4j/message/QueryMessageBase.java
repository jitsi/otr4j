package net.java.otr4j.message;

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
