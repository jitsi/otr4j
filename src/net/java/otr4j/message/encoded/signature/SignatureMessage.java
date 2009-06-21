package net.java.otr4j.message.encoded.signature;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import net.java.otr4j.message.MessageType;
import net.java.otr4j.message.encoded.DeserializationUtils;
import net.java.otr4j.message.encoded.SerializationUtils;

public final class SignatureMessage extends SignatureMessageBase {

	public SignatureMessage(int protocolVersion, byte[] mac, byte[] XBEncrypted)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {

		this.messageType = MessageType.SIGNATURE;
		this.protocolVersion = protocolVersion;
		this.signatureMac = mac;
		this.encryptedSignature = XBEncrypted;
	}

	public SignatureMessage() {

	}

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		SerializationUtils.writeShort(stream, this.protocolVersion);
		SerializationUtils.writeByte(stream, this.messageType);
		SerializationUtils.writeData(stream, this.encryptedSignature);
		SerializationUtils.writeData(stream, this.signatureMac);
	}

	public void readObject(java.io.ByteArrayInputStream stream) throws IOException {

		this.protocolVersion = DeserializationUtils.readShort(stream);
		this.messageType = DeserializationUtils.readByte(stream);
		this.encryptedSignature = DeserializationUtils.readData(stream);
		this.signatureMac = DeserializationUtils.readMac(stream);
	}
}
