package net.java.otr4j.message.unencoded;

import java.util.Vector;

public abstract class DiscoveryMessageBase extends UnencodedMessageBase {

	protected DiscoveryMessageBase(int messageType) {
		super(messageType);
	}

	public Vector<Integer> versions;
}
