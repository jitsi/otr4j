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
public class RevealSignatureMessage extends SignatureMessage {

	public byte[] revealedKey;

	public RevealSignatureMessage(int protocolVersion, byte[] xEncrypted,
			byte[] xEncryptedMAC, byte[] revealedKey)
	{
		super(MESSAGE_REVEALSIG, protocolVersion, xEncrypted, xEncryptedMAC);

		this.revealedKey = revealedKey;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(revealedKey);
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
		RevealSignatureMessage other = (RevealSignatureMessage) obj;
		if (!Arrays.equals(revealedKey, other.revealedKey))
			return false;
		return true;
	}
}
