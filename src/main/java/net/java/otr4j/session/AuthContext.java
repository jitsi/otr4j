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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrException;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureMessage;

/**
 * 
 * @author George Politis
 */
abstract class AuthContext {

	public static final int NONE = 0;
	public static final int AWAITING_DHKEY = 1;
	public static final int AWAITING_REVEALSIG = 2;
	public static final int AWAITING_SIG = 3;
	public static final int V1_SETUP = 4;
	public static final byte C_START = (byte) 0x01;
	public static final byte M1_START = (byte) 0x02;
	public static final byte M2_START = (byte) 0x03;
	public static final byte M1p_START = (byte) 0x04;
	public static final byte M2p_START = (byte) 0x05;

	// These parameters are initialized when generating D-H Commit Messages.
	// If the Session that this AuthContext belongs to is the 'master' session
	// then these parameters must be replicated to all slave session's auth contexts.
	byte[] r;
	KeyPair localDHKeyPair;
	byte[] localDHPublicKeyBytes;
	byte[] localDHPublicKeyHash;
	byte[] localDHPublicKeyEncrypted;

	abstract class MessageFactory {
		
		abstract QueryMessage getQueryMessage();
		
		abstract DHCommitMessage getDHCommitMessage() throws OtrException;
		
		abstract DHKeyMessage getDHKeyMessage() throws OtrException;
		
		abstract RevealSignatureMessage getRevealSignatureMessage() throws OtrException;
		
		abstract SignatureMessage getSignatureMessage() throws OtrException;
	}

	public abstract void reset();

	public abstract boolean getIsSecure();

	public abstract DHPublicKey getRemoteDHPublicKey();

	public abstract KeyPair getLocalDHKeyPair() throws OtrException;

	public abstract BigInteger getS() throws OtrException;

	public abstract void handleReceivingMessage(AbstractMessage m)
			throws OtrException;

	public abstract void startAuth() throws OtrException;

	public abstract DHCommitMessage respondAuth(Integer version) throws OtrException;

	public abstract PublicKey getRemoteLongTermPublicKey();

	public abstract KeyPair getLocalLongTermKeyPair() throws OtrException;
}