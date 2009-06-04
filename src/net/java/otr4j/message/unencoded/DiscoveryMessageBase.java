package net.java.otr4j.message.unencoded;

import java.util.Vector;

public abstract class DiscoveryMessageBase extends UnencodedMessageBase {

	protected DiscoveryMessageBase(int messageType) {
		super(messageType);
	}
	
	protected void setVersions(Vector<Integer> versions) {
		this.versions = versions;
	}

	public Vector<Integer> getVersions() {
		return versions;
	}

	private Vector<Integer> versions;
}
