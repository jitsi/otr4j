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

import javax.crypto.interfaces.DHPublicKey;

/**
 *
 * @author George Politis
 */
public class DataMessage extends AbstractEncodedMessage {

	// Fields.
	public byte[] mac;
	public byte[] oldMACKeys;

	public int flags;
	public int senderKeyID;
	public int recipientKeyID;
	public DHPublicKey nextDH;
	public byte[] ctr;
	public byte[] encryptedMessage;

	// Ctor.
	public DataMessage(int protocolVersion, int flags, int senderKeyID,
			int recipientKeyID, DHPublicKey nextDH, byte[] ctr,
			byte[] encryptedMessage, byte[] mac, byte[] oldMacKeys)
	{
		super(MESSAGE_DATA, protocolVersion);

		this.flags = flags;
		this.senderKeyID = senderKeyID;
		this.recipientKeyID = recipientKeyID;
		this.nextDH = nextDH;
		this.ctr = ctr;
		this.encryptedMessage = encryptedMessage;
		this.mac = mac;
		this.oldMACKeys = oldMacKeys;
	}

	public DataMessage(MysteriousT t, byte[] mac, byte[] oldMacKeys) {
		this(t.protocolVersion, t.flags, t.senderKeyID, t.recipientKeyID,
				t.nextDH, t.ctr, t.encryptedMessage, mac, oldMacKeys);
	}

	// Methods.
	public MysteriousT getT() {
		return new MysteriousT(protocolVersion, senderInstanceTag,
				receiverInstanceTag, flags, senderKeyID, recipientKeyID, nextDH,
				ctr, encryptedMessage);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(ctr);
		result = prime * result + Arrays.hashCode(encryptedMessage);
		result = prime * result + flags;
		result = prime * result + Arrays.hashCode(mac);
		// TODO: Needs work.
		result = prime * result + ((nextDH == null) ? 0 : nextDH.hashCode());
		result = prime * result + Arrays.hashCode(oldMACKeys);
		result = prime * result + recipientKeyID;
		result = prime * result + senderKeyID;
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
		DataMessage other = (DataMessage) obj;
		if (!Arrays.equals(ctr, other.ctr))
			return false;
		if (!Arrays.equals(encryptedMessage, other.encryptedMessage))
			return false;
		if (flags != other.flags)
			return false;
		if (!Arrays.equals(mac, other.mac))
			return false;
		if (nextDH == null) {
			if (other.nextDH != null)
				return false;
		} else if (!nextDH.equals(other.nextDH))
			return false;
		if (!Arrays.equals(oldMACKeys, other.oldMACKeys))
			return false;
		if (recipientKeyID != other.recipientKeyID)
			return false;
		if (senderKeyID != other.senderKeyID)
			return false;
		return true;
	}
}
