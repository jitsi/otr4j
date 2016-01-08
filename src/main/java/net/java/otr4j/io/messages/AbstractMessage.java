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

/**
 *
 * @author George Politis
 */
public abstract class AbstractMessage {
	// Fields.
	public int messageType;

	// Ctor.
	public AbstractMessage(int messageType) {
		this.messageType = messageType;
	}

	// Methods.
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + messageType;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AbstractMessage other = (AbstractMessage) obj;
		if (messageType != other.messageType)
			return false;
		return true;
	}

	// Unencoded
	public static final int MESSAGE_ERROR = 0xff;
	public static final int MESSAGE_QUERY = 0x100;
	public static final int MESSAGE_PLAINTEXT = 0x102;
}
