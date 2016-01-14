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

import javax.crypto.interfaces.DHPublicKey;

/**
 *
 * @author George Politis
 */
public class DHKeyMessage extends AbstractEncodedMessage {

	public DHPublicKey dhPublicKey;

	public DHKeyMessage(int protocolVersion, DHPublicKey dhPublicKey) {
		super(MESSAGE_DHKEY, protocolVersion);
		this.dhPublicKey = dhPublicKey;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		// TODO: Needs work.
		result = prime * result
				+ ((dhPublicKey == null) ? 0 : dhPublicKey.hashCode());
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
		DHKeyMessage other = (DHKeyMessage) obj;
		if (dhPublicKey == null) {
			if (other.dhPublicKey != null)
				return false;
		} else if (dhPublicKey.getY().compareTo(other.dhPublicKey.getY()) != 0)
			return false;
		return true;
	}
}
