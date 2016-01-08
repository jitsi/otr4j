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

import java.util.Arrays;

/**
 *
 * @author George Politis
 */
public class DHCommitMessage extends AbstractEncodedMessage {

	// Fields.
	public byte[] dhPublicKeyEncrypted;
	public byte[] dhPublicKeyHash;

	// Ctor.
	public DHCommitMessage(int protocolVersion, byte[] dhPublicKeyHash,
			byte[] dhPublicKeyEncrypted) {
		super(MESSAGE_DH_COMMIT, protocolVersion);
		this.dhPublicKeyEncrypted = dhPublicKeyEncrypted;
		this.dhPublicKeyHash = dhPublicKeyHash;
	}

	// Methods.
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(dhPublicKeyEncrypted);
		result = prime * result + Arrays.hashCode(dhPublicKeyHash);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		DHCommitMessage other = (DHCommitMessage) obj;
		if (!Arrays.equals(dhPublicKeyEncrypted, other.dhPublicKeyEncrypted))
			return false;
		if (!Arrays.equals(dhPublicKeyHash, other.dhPublicKeyHash))
			return false;
		return true;
	}

}
