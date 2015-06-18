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
public abstract interface OtrKeyManager {

	public abstract void addListener(OtrKeyManagerListener l);

	public abstract void removeListener(OtrKeyManagerListener l);

	public abstract void verify(SessionID sessionID);

	public abstract void unverify(SessionID sessionID);

	public abstract boolean isVerified(SessionID sessionID);

	public abstract String getRemoteFingerprint(SessionID sessionID);

	public abstract String getLocalFingerprint(SessionID sessionID);

	public abstract byte[] getLocalFingerprintRaw(SessionID sessionID);

	public abstract void savePublicKey(SessionID sessionID, PublicKey pubKey);

	public abstract PublicKey loadRemotePublicKey(SessionID sessionID);

	public abstract KeyPair loadLocalKeyPair(SessionID sessionID);

	public abstract void generateLocalKeyPair(SessionID sessionID);
}
