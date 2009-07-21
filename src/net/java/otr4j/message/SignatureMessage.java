package net.java.otr4j.message;

import java.io.*;
import java.security.*;
import javax.crypto.*;

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
