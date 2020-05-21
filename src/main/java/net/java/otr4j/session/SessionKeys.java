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

	int PREVIOUS = 0;
	int CURRENT = 1;
	/** @deprecated use {@link #PREVIOUS} instead */
	int Previous = PREVIOUS;
	/** @deprecated use {@link #CURRENT} instead */
	int Current = CURRENT;
	byte HIGH_SEND_BYTE = (byte) 0x01;
	byte HIGH_RECEIVE_BYTE = (byte) 0x02;
	byte LOW_SEND_BYTE = (byte) 0x02;
	byte LOW_RECEIVE_BYTE = (byte) 0x01;

	void setLocalPair(KeyPair keyPair, int localPairKeyID);

	void setRemoteDHPublicKey(DHPublicKey pubKey, int remoteKeyID);

	void incrementSendingCtr();

	byte[] getSendingCtr();

	byte[] getReceivingCtr();

	void setReceivingCtr(byte[] ctr);

	byte[] getSendingAESKey() throws OtrException;

	byte[] getReceivingAESKey() throws OtrException;

	byte[] getSendingMACKey() throws OtrException;

	byte[] getReceivingMACKey() throws OtrException;

	void setS(BigInteger s);

	void setIsUsedReceivingMACKey(Boolean isUsedReceivingMACKey);

	Boolean getIsUsedReceivingMACKey();

	int getLocalKeyID();

	int getRemoteKeyID();

	DHPublicKey getRemoteKey();

	KeyPair getLocalPair();
}
