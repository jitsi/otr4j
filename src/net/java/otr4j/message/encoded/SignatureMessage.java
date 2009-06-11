package net.java.otr4j.message.encoded;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.protocol.crypto.CryptoUtils;

public final class SignatureMessage extends SignatureMessageBase {

	public SignatureMessage(int protocolVersion, DHPublicKey pubKeyX,
			DHPublicKey pubKeyY, int keyidB, PrivateKey privKey,
			PublicKey pubKey, byte[] cp, byte[] m1p, byte[] m2p)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {
		this();
		byte[] MB = EncodedMessageUtils.computeMB(pubKeyX, pubKeyY, keyidB,
				pubKey, m1p);
		byte[] XB = EncodedMessageUtils.computeXB(privKey, pubKey, keyidB, MB);
		byte[] XBEncrypted = CryptoUtils.aesEncrypt(cp, XB);

		byte[] mac = CryptoUtils.sha256Hmac160(XBEncrypted, m2p);

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
		byte[] messageType = EncodedMessageUtils.serializeByte(this
				.getMessageType());
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
