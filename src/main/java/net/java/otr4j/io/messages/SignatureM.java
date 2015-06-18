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
package net.java.otr4j.io.messages;

import java.security.PublicKey;

import javax.crypto.interfaces.DHPublicKey;

/**
 * 
 * @author George Politis
 */
public class SignatureM {
	// Fields.
	public DHPublicKey localPubKey;
	public DHPublicKey remotePubKey;
	public PublicKey localLongTermPubKey;
	public int keyPairID;
	
	// Ctor.
	public SignatureM(DHPublicKey localPubKey, DHPublicKey remotePublicKey,
			PublicKey localLongTermPublicKey, int keyPairID) {

		this.localPubKey = localPubKey;
		this.remotePubKey = remotePublicKey;
		this.localLongTermPubKey = localLongTermPublicKey;
		this.keyPairID = keyPairID;
	}

	// Methods.
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + keyPairID;
		// TODO: Needs work.
		result = prime
				* result
				+ ((localLongTermPubKey == null) ? 0 : localLongTermPubKey
						.hashCode());
		result = prime * result
				+ ((localPubKey == null) ? 0 : localPubKey.hashCode());
		result = prime * result
				+ ((remotePubKey == null) ? 0 : remotePubKey.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		// TODO: Needs work.
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SignatureM other = (SignatureM) obj;
		if (keyPairID != other.keyPairID)
			return false;
		if (localLongTermPubKey == null) {
			if (other.localLongTermPubKey != null)
				return false;
		} else if (!localLongTermPubKey.equals(other.localLongTermPubKey))
			return false;
		if (localPubKey == null) {
			if (other.localPubKey != null)
				return false;
		} else if (!localPubKey.equals(other.localPubKey))
			return false;
		if (remotePubKey == null) {
			if (other.remotePubKey != null)
				return false;
		} else if (!remotePubKey.equals(other.remotePubKey))
			return false;
		return true;
	}

}
