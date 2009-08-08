package net.java.otr4j.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;

public abstract class SignatureMessageBase extends EncodedMessageBase {

	public SignatureMessageBase(int messageType) {
		super(messageType);
	}

	private byte[] xEncrypted;
	private byte[] xEncryptedMAC;

	public void setXEncryptedMAC(byte[] xEncryptedMAC) {
		this.xEncryptedMAC = xEncryptedMAC;
	}

	public byte[] getXEncryptedMAC() {
		return xEncryptedMAC;
	}

	public void setXEncrypted(byte[] xEncrypted) {
		this.xEncrypted = xEncrypted;
	}

	public byte[] getXEncrypted() {
		return xEncrypted;
	}

	protected byte[] hash(byte[] key) throws OtrException {

		ByteArrayOutputStream out_ = new ByteArrayOutputStream();
		byte[] tmp_;
		try {
			SerializationUtils.writeData(out_, this.xEncrypted);
			tmp_ = out_.toByteArray();
			out_.close();
		} catch (IOException e) {
			throw new OtrException(e);
		}

		byte[] xEncryptedMAC = new OtrCryptoEngineImpl().sha256Hmac160(tmp_, key);
		return xEncryptedMAC;
	}

	public byte[] decrypt(byte[] key) throws OtrException {
		return new OtrCryptoEngineImpl().aesDecrypt(key, null, this.xEncrypted);
	}

	public Boolean verify(byte[] key) throws OtrException {
		return Arrays.equals(this.hash(key), this.getXEncryptedMAC());
	}
}
