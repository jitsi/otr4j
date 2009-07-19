package net.java.otr4j.message.encoded.signature;

import java.io.*;
import java.security.*;
import java.util.Arrays;

import javax.crypto.*;

import net.java.otr4j.crypto.*;
import net.java.otr4j.message.encoded.*;

public abstract class SignatureMessageBase extends EncodedMessageBase {

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
