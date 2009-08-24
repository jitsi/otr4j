package net.java.otr4j;

import java.security.KeyPair;

import net.java.otr4j.session.SessionID;

public abstract interface OtrKeyManager {
	public abstract KeyPair getKeyPair(SessionID paramSessionID);
}
