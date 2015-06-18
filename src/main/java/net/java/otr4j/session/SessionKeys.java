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

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrException;

/**
 * @author George Politis
 */
public interface SessionKeys {

	public static final int Previous = 0;
	public static final int Current = 1;
	public static final byte HIGH_SEND_BYTE = (byte) 0x01;
	public static final byte HIGH_RECEIVE_BYTE = (byte) 0x02;
	public static final byte LOW_SEND_BYTE = (byte) 0x02;
	public static final byte LOW_RECEIVE_BYTE = (byte) 0x01;

	public abstract void setLocalPair(KeyPair keyPair, int localPairKeyID);

	public abstract void setRemoteDHPublicKey(DHPublicKey pubKey,
			int remoteKeyID);

	public abstract void incrementSendingCtr();

	public abstract byte[] getSendingCtr();

	public abstract byte[] getReceivingCtr();

	public abstract void setReceivingCtr(byte[] ctr);

	public abstract byte[] getSendingAESKey() throws OtrException;

	public abstract byte[] getReceivingAESKey() throws OtrException;

	public abstract byte[] getSendingMACKey() throws OtrException;

	public abstract byte[] getReceivingMACKey() throws OtrException;

	public abstract void setS(BigInteger s);

	public abstract void setIsUsedReceivingMACKey(Boolean isUsedReceivingMACKey);

	public abstract Boolean getIsUsedReceivingMACKey();

	public abstract int getLocalKeyID();

	public abstract int getRemoteKeyID();

	public abstract DHPublicKey getRemoteKey();

	public abstract KeyPair getLocalPair();

}