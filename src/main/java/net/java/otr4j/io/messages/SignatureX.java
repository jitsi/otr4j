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
import java.util.Arrays;

/**
 *
 * @author George Politis
 */
public class SignatureX {

	public PublicKey longTermPublicKey;
	public int dhKeyID;
	public byte[] signature;

	public SignatureX(PublicKey ourLongTermPublicKey, int ourKeyID, byte[] signature) {

		this.longTermPublicKey = ourLongTermPublicKey;
		this.dhKeyID = ourKeyID;
		this.signature = signature;
	}

	@Override
	public int hashCode() {
		// TODO: Needs work.
		final int prime = 31;
		int result = 1;
		result = prime * result + dhKeyID;
		result = prime
				* result
				+ ((longTermPublicKey == null) ? 0 : longTermPublicKey
						.hashCode());
		result = prime * result + Arrays.hashCode(signature);
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
		SignatureX other = (SignatureX) obj;
		if (dhKeyID != other.dhKeyID)
			return false;
		if (longTermPublicKey == null) {
			if (other.longTermPublicKey != null)
				return false;
		} else if (!longTermPublicKey.equals(other.longTermPublicKey))
			return false;
		if (!Arrays.equals(signature, other.signature))
			return false;
		return true;
	}
}
