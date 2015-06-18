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
import java.util.List;

import net.java.otr4j.OtrEngineListener;
import net.java.otr4j.OtrException;
import net.java.otr4j.OtrPolicy;
import net.java.otr4j.io.messages.AbstractMessage;

/**
 * @author George Politis
 */
public interface Session {

	public static interface OTRv {
		public static final int ONE = 1;

		public static final int TWO = 2;

		public static final int THREE = 3;
	}

	public abstract SessionStatus getSessionStatus();

	public abstract SessionID getSessionID();

	public abstract void injectMessage(AbstractMessage m) throws OtrException;

	public abstract KeyPair getLocalKeyPair() throws OtrException;

	public abstract OtrPolicy getSessionPolicy();

	public abstract String transformReceiving(String content)
			throws OtrException;

	public abstract String[] transformSending(String content, List<TLV> tlvs)
			throws OtrException;

	public abstract String[] transformSending(String content)
			throws OtrException;

	public abstract void startSession() throws OtrException;

	public abstract void endSession() throws OtrException;

	public abstract void refreshSession() throws OtrException;

	public abstract PublicKey getRemotePublicKey();

	public abstract void addOtrEngineListener(OtrEngineListener l);

	public abstract void removeOtrEngineListener(OtrEngineListener l);

	public abstract void initSmp(String question, String secret)
			throws OtrException;

	public abstract void respondSmp(String question, String secret)
			throws OtrException;

	public abstract void abortSmp() throws OtrException;
	
	public abstract boolean isSmpInProgress();

	public abstract BigInteger getS();

	// OTRv3 methods
	public abstract List<Session> getInstances();

	public abstract Session getOutgoingInstance();

	public abstract boolean setOutgoingInstance(InstanceTag tag);

	public abstract InstanceTag getSenderInstanceTag();

	public abstract InstanceTag getReceiverInstanceTag();

	public abstract void setReceiverInstanceTag(InstanceTag tag);

	public abstract void setProtocolVersion(int protocolVersion);

	public abstract int getProtocolVersion();

	public abstract void respondSmp(
			InstanceTag receiverTag, String question, String secret)
					throws OtrException;

	public abstract SessionStatus getSessionStatus(InstanceTag tag);

	public abstract PublicKey getRemotePublicKey(InstanceTag tag);
}