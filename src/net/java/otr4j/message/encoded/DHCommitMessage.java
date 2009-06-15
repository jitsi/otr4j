package net.java.otr4j.message.encoded;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.protocol.crypto.CryptoUtils;

public final class DHCommitMessage extends EncodedMessageBase {

	public byte[] gxEncrypted;
	public byte[] gxHash;

	private DHCommitMessage() {
		super(MessageType.DH_COMMIT);
	}

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

		// Encrypted gx (DATA)
		byte[] serializedGxEncrypted = EncodedMessageUtils
				.serializeData(this.gxEncrypted);
		len += serializedGxEncrypted.length;

		// Hashed gx (DATA)
		byte[] serializedGxHash = EncodedMessageUtils
				.serializeData(this.gxHash);
		len += serializedGxHash.length;

		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(serializedGxEncrypted);
		buff.put(serializedGxHash);

		String encodedMessage = EncodedMessageUtils.encodeMessage(buff.array());
		return encodedMessage;
	}

	public DHCommitMessage(String msgText) {
		this();

		if (msgText == null || !msgText.startsWith(MessageHeader.DH_COMMIT))
			return;

		byte[] decodedMessage = EncodedMessageUtils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = EncodedMessageUtils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = EncodedMessageUtils.deserializeByte(buff);
		if (msgType != MessageType.DH_COMMIT)
			return;

		// Encrypted gx (DATA)
		byte[] gx = EncodedMessageUtils.deserializeData(buff);

		// Hashed gx (DATA)
		byte[] gxHash = EncodedMessageUtils.deserializeData(buff);

		this.protocolVersion = protocolVersion;
		this.gxEncrypted = gx;
		this.gxHash = gxHash;
	}

	public DHCommitMessage(int protocolVersion, byte[] r, DHPublicKey gxKey)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		this();

		// Get gx.
		byte[] gx = ((DHPublicKey) gxKey).getY().toByteArray();

		byte[] gxHash = CryptoUtils.sha256Hash(gx);
		
		// Encrypt gx.
		byte[] gxEncrypted = CryptoUtils.aesEncrypt(r, gx);
		
		this.protocolVersion = protocolVersion;
		this.gxEncrypted = gxEncrypted;
		this.gxHash = gxHash;
	}
}
