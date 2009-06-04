package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.java.otr4j.message.MessageHeader;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class Utils {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	protected static byte[] decodeMessage(String msg) {
		int end = msg.lastIndexOf(".");

		if (msg.indexOf(MessageHeader.ENCODED_MESSAGE) != 0
				|| end != msg.length() - 1)
			throw new IllegalArgumentException();

		String base64 = msg.substring(MessageHeader.ENCODED_MESSAGE.length(),
				end);
		byte[] decodedMessage = Base64.decodeBase64(base64.getBytes());
		return decodedMessage;
	}

	public static String encodeMessage(byte[] msg) {
		if (msg == null || msg.length < 1)
			return "";

		byte[] encodedMessage = Base64.encodeBase64(msg);
		return MessageHeader.ENCODED_MESSAGE + new String(encodedMessage) + ".";
	}

	public static byte[] sign(byte[] b, PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		Signature sign = Signature.getInstance(privateKey.getAlgorithm());
		sign.initSign(privateKey);
		sign.update(b);
		return sign.sign();
	}

	public static byte[] sha256Hmac(byte[] b, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException {
		return sha256Hmac(b, key, 0);
	}

	public static byte[] sha256Hmac(byte[] b, byte[] key, int length)
			throws NoSuchAlgorithmException, InvalidKeyException {

		SecretKeySpec keyspec = new SecretKeySpec(key, "HmacSHA256");
		javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
		mac.init(keyspec);

		byte[] macBytes = mac.doFinal(b);

		if (length > 0) {
			byte[] bytes = new byte[length];
			ByteBuffer buff = ByteBuffer.wrap(macBytes);
			buff.get(bytes);
			return bytes;
		} else {
			return macBytes;
		}
	}

	public static byte[] sha256Hmac160(byte[] b, byte[] key)
			throws NoSuchAlgorithmException, InvalidKeyException {
		return sha256Hmac(b, key, 20);
	}

	public static byte[] sha256Hash(byte[] b) throws NoSuchAlgorithmException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		sha256.update(b, 0, b.length);
		return sha256.digest();
	}

	public static byte[] aesEncrypt(byte[] key, byte[] b)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {

		// Create cipher KeySpec based on r.
		SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
		// Create initial counter value 0.
		IvParameterSpec spec = new IvParameterSpec(CryptoConstants.ZERO_CTR);

		// Initialize cipher.
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, keyspec, spec);

		return cipher.doFinal(b);
	}

	private static byte[] intToByteArray(int value, int length) {
		byte[] b = new byte[length];
		for (int i = 0; i < length; i++) {
			int offset = (b.length - 1 - i) * 8;
			b[i] = (byte) ((value >>> offset) & 0xFF);
		}
		return b;
	}

	private static int byteArrayToInt(byte[] b) {
		int value = 0;
		for (int i = 0; i < b.length; i++) {
			int shift = (b.length - 1 - i) * 8;
			value += (b[i] & 0x000000FF) << shift;
		}
		return value;
	}

	public static byte[] serializeShort(int n) {
		return intToByteArray(n, DataLength.SHORT);
	}

	public static byte[] serializeByte(int n) {
		return intToByteArray(n, DataLength.SHORT);
	}

	public static byte[] serializeInt(int n) {
		return intToByteArray(n, DataLength.INT);
	}

	public static byte[] serializeData(byte[] b) {
		byte[] len = intToByteArray(b.length, DataLength.SHORT);

		ByteBuffer buff = ByteBuffer.allocate(b.length + len.length);
		buff.put(len);
		buff.put(b);
		return buff.array();
	}

	public static byte[] serializeDHPublicKey(DHPublicKey pubKey) {
		return serializeMpi(((DHPublicKey) pubKey).getY());
	}

	private static byte[] serializeMpi(BigInteger i) {
		return serializeData(i.toByteArray());
	}

	public static byte[] serializeDsaPublicKey(PublicKey pubKey)
			throws InvalidKeyException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new InvalidKeyException();

		DSAPublicKey dsaKey = (DSAPublicKey) pubKey;

		byte[] type = CryptoConstants.DSA_PUB_TYPE;

		DSAParams dsaParams = dsaKey.getParams();
		byte[] serializedP = serializeMpi(dsaParams.getP());
		byte[] serializedQ = serializeMpi(dsaParams.getQ());
		byte[] serializedG = serializeMpi(dsaParams.getG());
		byte[] serializedY = serializeMpi(dsaKey.getY());

		int len = type.length + serializedP.length + serializedQ.length
				+ serializedG.length + serializedY.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(type);
		buff.put(serializedP);
		buff.put(serializedQ);
		buff.put(serializedG);
		buff.put(serializedY);

		return buff.array();
	}

	public static int deserializeShort(ByteBuffer buff) {
		byte[] b = new byte[DataLength.SHORT];
		buff.get(b);
		return byteArrayToInt(b);
	}

	public static int deserializeByte(ByteBuffer buff) {
		byte[] b = new byte[DataLength.BYTE];
		buff.get(b);
		return byteArrayToInt(b);
	}

	private static int deserializeDataLen(ByteBuffer buff) {
		byte[] b = new byte[DataLength.DATALEN];
		buff.get(b);
		return byteArrayToInt(b);
	}

	public static byte[] deserializeData(ByteBuffer buff) {
		int len = deserializeDataLen(buff);

		byte[] b = new byte[len];
		buff.get(b);
		return b;
	}

	public static byte[] deserializeMac(ByteBuffer buff) {
		byte[] b = new byte[DataLength.MAC];
		buff.get(b);
		return b;
	}

	public static BigInteger deserializeMpi(ByteBuffer buff) {
		int len = deserializeDataLen(buff);

		byte[] b = new byte[len];
		buff.get(b);

		// MPIs must use the minimum-length encoding; i.e. no leading 0x00
		// bytes.
		byte[] bTrimmed = trim(b);
		return new BigInteger(1, bTrimmed);
	}

	private static byte[] trim(byte[] b) {
		// find leading zero count
		int i = 0;
		while ((int) b[i] == 0)
			i++;

		// remove leading 0's
		byte[] tmp = new byte[b.length - i];
		for (int j = 0; j < tmp.length; j++)
			tmp[j] = b[j + i];

		return tmp;
	}

	public static int deserializeInt(ByteBuffer buff) {
		byte[] b = new byte[DataLength.INT];
		buff.get(b);
		return byteArrayToInt(b);
	}

	public static byte[] deserializeCtr(ByteBuffer buff) {
		byte[] b = new byte[DataLength.CTR];
		buff.get(b);
		return b;
	}

	private static byte[] h2(byte b, BigInteger s)
			throws NoSuchAlgorithmException {
		byte[] secbytes = serializeMpi(s);

		int len = secbytes.length + 1;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(b);
		buff.put(secbytes);
		return sha256Hash(buff.array());
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

	public static KeyPair generateDsaKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
		return kg.genKeyPair();
	}

	public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
		DHParameterSpec dhSpec = new DHParameterSpec(CryptoConstants.MODULUS,
				CryptoConstants.GENERATOR,
				CryptoConstants.DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH);

		keyGen.initialize(dhSpec);

		return keyGen.generateKeyPair();
	}

	public static byte[] getRandomBytes(int length) {
		byte[] b = new byte[length];
		Random rnd = new Random();
		rnd.nextBytes(b);
		return b;
	}

	public static DHPublicKey getDHPublicKey(BigInteger mpi)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		DHPublicKeySpec pubKeySpecs = new DHPublicKeySpec(mpi,
				CryptoConstants.MODULUS, CryptoConstants.GENERATOR);

		KeyFactory keyFac = KeyFactory.getInstance("DH");
		return (DHPublicKey) keyFac.generatePublic(pubKeySpecs);

	}

	public static BigInteger getSecretKey(KeyPair dhKeyPairX, KeyPair dhKeyPairY)
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(dhKeyPairX.getPrivate());
		ka.doPhase(dhKeyPairY.getPublic(), true);
		BigInteger s = new BigInteger(ka.generateSecret());
		return s;
	}

}
