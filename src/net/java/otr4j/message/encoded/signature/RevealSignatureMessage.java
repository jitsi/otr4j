package net.java.otr4j.message.encoded.signature;

import java.nio.ByteBuffer;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.DataLength;
import net.java.otr4j.message.encoded.EncodedMessageUtils;

public final class RevealSignatureMessage extends SignatureMessageBase {

	public RevealSignatureMessage(int protocolVersion, byte[] r, byte[] mac,
			byte[] XBEncrypted) {
		this();

		this.protocolVersion = protocolVersion;
		this.signatureMac = mac;
		this.encryptedSignature = XBEncrypted;
		this.revealedKey = r;
	}

	private RevealSignatureMessage() {
		super(MessageType.REVEALSIG);
	}

	public byte[] revealedKey;

	public String toString() {
		int len = 0;
		// Protocol version (SHORT)
		byte[] protocolVersion = EncodedMessageUtils
				.serializeShort(this.protocolVersion);
		len += protocolVersion.length;

		// Message type (BYTE)
		byte[] messageType = EncodedMessageUtils
				.serializeByte(this.messageType);
		len += messageType.length;

		// Revealed key (DATA)
		byte[] serializedRevealedKey = EncodedMessageUtils
				.serializeData(this.revealedKey);
		len += serializedRevealedKey.length;

		// Encrypted Signature (DATA)
		byte[] serializedSig = EncodedMessageUtils
				.serializeData(this.encryptedSignature);
		len += serializedSig.length;

		// MAC'd signature (MAC)
		byte[] mac = this.signatureMac;
		len += DataLength.MAC;

		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(serializedRevealedKey);
		buff.put(serializedSig);
		buff.put(mac);

		String encodedMessage = EncodedMessageUtils.encodeMessage(buff.array());
		return encodedMessage;
	}

	public RevealSignatureMessage(String msgText) {
		this();

		byte[] decodedMessage = EncodedMessageUtils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = EncodedMessageUtils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = EncodedMessageUtils.deserializeByte(buff);
		if (msgType != MessageType.REVEALSIG)
			return;

		// Revealed key (DATA)
		byte[] revealedKey = EncodedMessageUtils.deserializeData(buff);

		// Encrypted Signature (DATA)
		byte[] sig = EncodedMessageUtils.deserializeData(buff);

		// MAC'd signature (MAC)
		byte[] mac = EncodedMessageUtils.deserializeMac(buff);

		this.protocolVersion = protocolVersion;
		this.revealedKey = revealedKey;
		this.encryptedSignature = sig;
		this.signatureMac = mac;
	}
}
