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
package net.java.otr4j;

import java.security.KeyPair;
import java.security.PublicKey;

import net.java.otr4j.session.SessionID;

/**
 * @author George Politis
 */
public interface OtrKeyManager {

	void addListener(OtrKeyManagerListener l);

	void removeListener(OtrKeyManagerListener l);

	void verify(SessionID sessionID);

	void unverify(SessionID sessionID);

	boolean isVerified(SessionID sessionID);

	String getRemoteFingerprint(SessionID sessionID);

	String getLocalFingerprint(SessionID sessionID);

	byte[] getLocalFingerprintRaw(SessionID sessionID);

	void savePublicKey(SessionID sessionID, PublicKey pubKey);

	PublicKey loadRemotePublicKey(SessionID sessionID);

	KeyPair loadLocalKeyPair(SessionID sessionID);

	void generateLocalKeyPair(SessionID sessionID);
}
