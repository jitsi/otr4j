package net.java.otr4j.message;

import java.util.*;

public abstract class QueryMessageBase extends MessageBase {
	public Vector<Integer> versions;
	
	public QueryMessageBase(int messageType){
		super(messageType);
	}
}
