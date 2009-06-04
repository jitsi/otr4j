package net.java.otr4j.message.encoded;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import javax.crypto.interfaces.DHPublicKey;

public abstract class SignatureMessageBase extends EncodedMessageBase {

	private byte[] encryptedSignature;
	private byte[] signatureMac;

	protected void setEncryptedSignature(byte[] sig) {
		this.encryptedSignature = sig;
	}

	public byte[] getEncryptedSignature() {
		return encryptedSignature;
	}

	protected void setSignatureMac(byte[] mac) {
		this.signatureMac = mac;
	}

	public byte[] getSignatureMac() {
		return signatureMac;
	}

	protected SignatureMessageBase(int messageType) {
		super(messageType);
	}

	protected static byte[] computeXB(PrivateKey privKey, PublicKey pubKey,
			int keyidB, byte[] MB) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException {

		byte[] pubBBytes = Utils.serializeDsaPublicKey(pubKey);
		byte[] keyidBBytes = Utils.serializeInt(keyidB);
		byte[] sigB = Utils.sign(MB, privKey);

		int len = pubBBytes.length + keyidBBytes.length + sigB.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(pubBBytes);
		buff.put(keyidBBytes);
		buff.put(sigB);
		return buff.array();
	}

	protected static byte[] computeMB(DHPublicKey gxKey, DHPublicKey gyKey,
			int keyidB, PublicKey pubB, byte[] m1) throws InvalidKeyException,
			NoSuchAlgorithmException {

		byte[] gx = Utils.serializeDHPublicKey(gxKey);
		byte[] gy = Utils.serializeDHPublicKey(gyKey);
		byte[] keyidBytes = Utils.serializeInt(keyidB);
		byte[] pub = Utils.serializeDsaPublicKey(pubB);

		int len = gx.length + gy.length + pub.length + keyidBytes.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(gx);
		buff.put(gy);
		buff.put(pub);
		buff.put(keyidBytes);

		return Utils.sha256Hmac(buff.array(), m1);
	}
}
