package net.java.otr4j.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import net.java.otr4j.CryptoUtils;


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

	protected byte[] hash(byte[] key) throws IOException, InvalidKeyException,
			NoSuchAlgorithmException {

		ByteArrayOutputStream out_ = new ByteArrayOutputStream();
		SerializationUtils.writeData(out_, this.xEncrypted);
		byte[] tmp_ = out_.toByteArray();
		out_.close();

		byte[] xEncryptedMAC = CryptoUtils.sha256Hmac160(tmp_, key);
		return xEncryptedMAC;
	}

	public byte[] decrypt(byte[] key) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return CryptoUtils.aesDecrypt(key, null, this.xEncrypted);
	}

	public Boolean verify(byte[] key) throws InvalidKeyException,
			NoSuchAlgorithmException, IOException {
		return Arrays.equals(this.hash(key), this.getXEncryptedMAC());
	}
}
