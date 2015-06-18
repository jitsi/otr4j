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
public abstract class AbstractEncodedMessage extends AbstractMessage {
	// Fields.
	public int protocolVersion;

	public int senderInstanceTag;

	public int receiverInstanceTag;

	// Ctor.
	public AbstractEncodedMessage(int messageType, int protocolVersion) {
		super(messageType);
		this.protocolVersion = protocolVersion;
	}

	public AbstractEncodedMessage(
			int messageType, int protocolVersion, int senderInstanceTag) {
		this(messageType, protocolVersion, senderInstanceTag, 0);
	}

	public AbstractEncodedMessage(  int messageType,
									int protocolVersion,
									int senderInstanceTag,
									int recipientInstanceTag) {
		super(messageType);
		this.protocolVersion = protocolVersion;
		this.senderInstanceTag = senderInstanceTag;
		this.receiverInstanceTag = recipientInstanceTag;
	}

	// Methods.
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + protocolVersion;
		result = prime * result + senderInstanceTag;
		result = prime * result + receiverInstanceTag;
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
		AbstractEncodedMessage other = (AbstractEncodedMessage) obj;
		if (protocolVersion != other.protocolVersion)
			return false;
		if (senderInstanceTag != other.senderInstanceTag)
			return false;
		if (receiverInstanceTag != other.receiverInstanceTag)
			return false;
		return true;
	}

	// Encoded Message Types
	public static final int MESSAGE_DH_COMMIT = 0x02;
	public static final int MESSAGE_DATA = 0x03;
	public static final int MESSAGE_DHKEY = 0x0a;
	public static final int MESSAGE_REVEALSIG = 0x11;
	public static final int MESSAGE_SIGNATURE = 0x12;
}
