package net.java.otr4j.message;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public final class SignatureMessage extends SignatureMessageBase {

	public SignatureMessage(int protocolVersion, byte[] xEncryptedMAC,
			byte[] xEncrypted) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, SignatureException {
		super(MessageConstants.SIGNATURE);
		this.setProtocolVersion(protocolVersion);
		this.setXEncryptedMAC(xEncryptedMAC);
		this.setXEncrypted(xEncrypted);
	}

	public SignatureMessage() {
		super(MessageConstants.SIGNATURE);
	}

	public void writeObject(OutputStream out) throws IOException {

		SerializationUtils.writeShort(out, this.getProtocolVersion());
		SerializationUtils.writeByte(out, this.getMessageType());
		SerializationUtils.writeData(out, this.getXEncrypted());
		SerializationUtils.writeMac(out, this.getXEncryptedMAC());
	}

	public void readObject(InputStream in) throws IOException {

		this.setProtocolVersion(SerializationUtils.readShort(in));
		this.setMessageType(SerializationUtils.readByte(in));
		this.setXEncrypted(SerializationUtils.readData(in));
		this.setXEncryptedMAC(SerializationUtils.readMac(in));
	}
}
