package net.java.otr4j.message.encoded;

import java.io.*;
import java.security.*;

import javax.crypto.*;

import net.java.otr4j.*;
import net.java.otr4j.crypto.*;

public class MysteriousX implements OtrSerializable {

	public MysteriousX() {

	}

	public MysteriousX(PublicKey ourLongTermPublicKey, int ourKeyID,
			byte[] signature) {
		this.setDhKeyID(ourKeyID);
		this.setLongTermPublicKey(ourLongTermPublicKey);
		this.setSignature(signature);
	}

	public void readObject(byte[] b) throws IOException {
		ByteArrayInputStream bis = null;
		try {
			bis = new ByteArrayInputStream(b);
			this.readObject(bis);
		} catch (Exception e) {
			bis.close();
		}
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException {
		try {
			this.setLongTermPublicKey(DeserializationUtils
					.readPublicKey(stream));
		} catch (Exception e) {
			throw new IOException(e);
		}
		this.setDhKeyID(DeserializationUtils.readInt(stream));
		this.setSignature(DeserializationUtils.readSignature(stream, this
				.getLongTermPublicKey()));
	}

	private PublicKey longTermPublicKey;
	private int dhKeyID;
	private byte[] signature;

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		try {
			SerializationUtils.writePublicKey(stream, this
					.getLongTermPublicKey());
		} catch (Exception e) {
			throw new IOException(e);
		}
		SerializationUtils.writeInt(stream, this.getDhKeyID());
		SerializationUtils.writeSignature(stream, this.getSignature(), this
				.getLongTermPublicKey());
	}

	public void setLongTermPublicKey(PublicKey longTermPublicKey) {
		this.longTermPublicKey = longTermPublicKey;
	}

	public PublicKey getLongTermPublicKey() {
		return longTermPublicKey;
	}

	public void setDhKeyID(int dhKeyID) {
		this.dhKeyID = dhKeyID;
	}

	public int getDhKeyID() {
		return dhKeyID;
	}

	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public byte[] getSignature() {
		return signature;
	}

	public byte[] encrypted;
	public byte[] hash;

	public void update(byte[] encryptionKey, byte[] hashKey)
			throws InvalidKeyException, IOException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		ByteArrayOutputStream localXbos = new ByteArrayOutputStream();
		this.writeObject(localXbos);
		byte[] localXbytes = localXbos.toByteArray();
		encrypted = CryptoUtils.aesEncrypt(encryptionKey, null, localXbytes);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		SerializationUtils.writeData(out, encrypted);
		byte[] tmp = out.toByteArray();
		out.close();

		hash = CryptoUtils.sha256Hmac160(tmp, hashKey);
	}

}
