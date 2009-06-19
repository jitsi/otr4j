package net.java.otr4j.message.unencoded.query;

import java.util.Vector;

import net.java.otr4j.message.unencoded.UnencodedMessageBase;

public abstract class QueryMessageBase extends UnencodedMessageBase {

	protected QueryMessageBase(int messageType) {
		super(messageType);
	}

	public Vector<Integer> versions;
}
