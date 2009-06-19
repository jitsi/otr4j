package net.java.otr4j.message.encoded.signature;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.DataLength;
import net.java.otr4j.message.encoded.EncodedMessageUtils;

public final class SignatureMessage extends SignatureMessageBase {

	public SignatureMessage(int protocolVersion, byte[] mac,
			byte[] XBEncrypted)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {
		this();

		this.protocolVersion = protocolVersion;
		this.signatureMac = mac;
		this.encryptedSignature = XBEncrypted;
	}

	private SignatureMessage() {
		super(MessageType.SIGNATURE);
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

		// Encrypted signature (DATA)
		byte[] serializedEncryptedSignature = EncodedMessageUtils
				.serializeData(this.encryptedSignature);
		len += serializedEncryptedSignature.length;

		// MAC'd signature (MAC)
		byte[] serializedSignatureMac = this.signatureMac;
		len += DataLength.MAC;

		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(serializedEncryptedSignature);
		buff.put(serializedSignatureMac);

		String encodedMessage = EncodedMessageUtils.encodeMessage(buff.array());
		return encodedMessage;
	}

	public SignatureMessage(String msgText) {
		this();

		if (!msgText.startsWith(MessageHeader.SIGNATURE))
			return;

		byte[] decodedMessage = EncodedMessageUtils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = EncodedMessageUtils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = EncodedMessageUtils.deserializeByte(buff);
		if (msgType != MessageType.SIGNATURE)
			return;

		// Encrypted Signature (DATA)
		byte[] sig = EncodedMessageUtils.deserializeData(buff);

		// MAC'd signature (MAC)
		byte[] mac = EncodedMessageUtils.deserializeMac(buff);

		this.protocolVersion = protocolVersion;
		this.encryptedSignature = sig;
		this.signatureMac = mac;
	}
}
