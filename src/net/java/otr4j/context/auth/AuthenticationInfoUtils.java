package net.java.otr4j.context.auth;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.crypto.CryptoConstants;
import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.encoded.EncodedMessageUtils;

public class AuthenticationInfoUtils {
	private static byte[] sign(byte[] b, PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		Signature sign = Signature.getInstance(privateKey.getAlgorithm());
		sign.initSign(privateKey);
		sign.update(b);
		return sign.sign();
	}

	public static byte[] computeX(PrivateKey privKey, PublicKey pubKey,
			int keyidB, byte[] MB) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException {

		byte[] pubBBytes = EncodedMessageUtils.serializeDsaPublicKey(pubKey);
		byte[] keyidBBytes = EncodedMessageUtils.serializeInt(keyidB);
		byte[] sigB = sign(MB, privKey);

		int len = pubBBytes.length + keyidBBytes.length + sigB.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(pubBBytes);
		buff.put(keyidBBytes);
		buff.put(sigB);
		return buff.array();
	}

	public static byte[] computeM(DHPublicKey gxKey, DHPublicKey gyKey,
			int keyidB, PublicKey pubB, byte[] m1) throws InvalidKeyException,
			NoSuchAlgorithmException {

		byte[] gx = EncodedMessageUtils.serializeDHPublicKey(gxKey);
		byte[] gy = EncodedMessageUtils.serializeDHPublicKey(gyKey);
		byte[] keyidBytes = EncodedMessageUtils.serializeInt(keyidB);
		byte[] pub = EncodedMessageUtils.serializeDsaPublicKey(pubB);

		int len = gx.length + gy.length + pub.length + keyidBytes.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(gx);
		buff.put(gy);
		buff.put(pub);
		buff.put(keyidBytes);

		return CryptoUtils.sha256Hmac(buff.array(), m1);
	}

	private static byte[] h2(byte b, BigInteger s)
			throws NoSuchAlgorithmException {
		byte[] secbytes = EncodedMessageUtils.serializeMpi(s);

		int len = secbytes.length + 1;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(b);
		buff.put(secbytes);
		return CryptoUtils.sha256Hash(buff.array());
	}

	public static byte[] getSSID(BigInteger s) throws NoSuchAlgorithmException {
		byte[] h2 = h2(CryptoConstants.SSID_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);

		byte[] ssid = new byte[CryptoConstants.SSID_LENGTH];
		buff.get(ssid);
		return ssid;
	}

	public static byte[] getC(BigInteger s) throws NoSuchAlgorithmException {
		byte[] h2 = h2(CryptoConstants.C_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] c = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		buff.get(c);
		return c;
	}

	public static byte[] getCp(BigInteger s) throws NoSuchAlgorithmException {
		byte[] h2 = h2(CryptoConstants.C_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] cp = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		buff.position(CryptoConstants.AES_KEY_BYTE_LENGTH);
		buff.get(cp);
		return cp;
	}

	public static byte[] getM1(BigInteger s) throws NoSuchAlgorithmException {
		byte[] h2 = h2(CryptoConstants.M1_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}

	public static byte[] getM1p(BigInteger s) throws NoSuchAlgorithmException {
		byte[] h2 = h2(CryptoConstants.M1p_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}

	public static byte[] getM2(BigInteger s) throws NoSuchAlgorithmException {
		byte[] h2 = h2(CryptoConstants.M2_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}

	public static byte[] getM2p(BigInteger s) throws NoSuchAlgorithmException {
		byte[] h2 = h2(CryptoConstants.M2p_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}
}
