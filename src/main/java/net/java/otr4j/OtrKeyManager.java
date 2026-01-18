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

	/**
	 * Adds listener to key manager
	 */
	void addListener(OtrKeyManagerListener l);

	/**
	 * Remove listener from key manager
	 */
	void removeListener(OtrKeyManagerListener l);

	/**
	 * Verify the specified sessionID
	 */
	void verify(SessionID sessionID);

	/**
	 * Removes the verification for the specified sessionID
	 */
	void unverify(SessionID sessionID);

	/**
	 * Check if the specified sessionID is verified for this machine
	 */
	boolean isVerified(SessionID sessionID);

	/**
	 * Return remote contact's fingerprint for specified sessionID.
	 */
	String getRemoteFingerprint(SessionID sessionID);

	/**
	 * Returns the local fingerprint for specified session.
	 * If there is no fingerprint you might generate one.
	 */
	String getLocalFingerprint(SessionID sessionID);

	byte[] getLocalFingerprintRaw(SessionID sessionID);

	/**
	 * Stores the public key for a specified user from sessionID
	 *
	 * @param sessionID sessionID to identify the owner of the key
	 * @param pubKey    the key which should be stored
	 */
	void savePublicKey(SessionID sessionID, PublicKey pubKey);

	/**
	 * Loads the public key for the specified sessionID.
	 * If there is no key stored, you will get 'null'
	 */
	PublicKey loadRemotePublicKey(SessionID sessionID);

	/**
	 * Returns the key pair (private and public key) for the local machine
	 *
	 * @param sessionID sessionID for current machine
	 */
	KeyPair loadLocalKeyPair(SessionID sessionID);

	/**
	 * Generate your own local pair of public and private keys.
	 * Be careful: if there is already a key pair it will override it.
	 *
	 * @param sessionID the sessionID that has AccountID to identify with the local machine
	 */
	void generateLocalKeyPair(SessionID sessionID);
}
