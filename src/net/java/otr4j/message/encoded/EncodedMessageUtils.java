package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.protocol.crypto.CryptoConstants;
import net.java.otr4j.protocol.crypto.CryptoUtils;
import net.java.otr4j.utils.Utils;
import org.apache.commons.codec.binary.Base64;

public final class EncodedMessageUtils {

	static byte[] decodeMessage(String msg) {
		int end = msg.lastIndexOf(".");

		if (msg.indexOf(MessageHeader.ENCODED_MESSAGE) != 0
				|| end != msg.length() - 1)
			throw new IllegalArgumentException();

		String base64 = msg.substring(MessageHeader.ENCODED_MESSAGE.length(),
				end);
		byte[] decodedMessage = Base64.decodeBase64(base64.getBytes());
		return decodedMessage;
	}

	static String encodeMessage(byte[] msg) {
		if (msg == null || msg.length < 1)
			return "";

		byte[] encodedMessage = Base64.encodeBase64(msg);
		return MessageHeader.ENCODED_MESSAGE + new String(encodedMessage) + ".";
	}

	private static byte[] sign(byte[] b, PrivateKey privateKey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		Signature sign = Signature.getInstance(privateKey.getAlgorithm());
		sign.initSign(privateKey);
		sign.update(b);
		return sign.sign();
	}

	static byte[] serializeShort(int n) {
		return Utils.intToByteArray(n, DataLength.SHORT);
	}

	static byte[] serializeByte(int n) {
		return Utils.intToByteArray(n, DataLength.SHORT);
	}

	private static byte[] serializeInt(int n) {
		return Utils.intToByteArray(n, DataLength.INT);
	}

	static byte[] serializeData(byte[] b) {
		byte[] len = Utils.intToByteArray(b.length, DataLength.SHORT);

		ByteBuffer buff = ByteBuffer.allocate(b.length + len.length);
		buff.put(len);
		buff.put(b);
		return buff.array();
	}

	static byte[] serializeDHPublicKey(DHPublicKey pubKey) {
		return serializeMpi(((DHPublicKey) pubKey).getY());
	}

	public static byte[] serializeMpi(BigInteger i) {
		return serializeData(i.toByteArray());
	}

	private static byte[] serializeDsaPublicKey(PublicKey pubKey)
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

	static int deserializeShort(ByteBuffer buff) {
		byte[] b = new byte[DataLength.SHORT];
		buff.get(b);
		return Utils.byteArrayToInt(b);
	}

	static int deserializeByte(ByteBuffer buff) {
		byte[] b = new byte[DataLength.BYTE];
		buff.get(b);
		return Utils.byteArrayToInt(b);
	}

	private static int deserializeDataLen(ByteBuffer buff) {
		byte[] b = new byte[DataLength.DATALEN];
		buff.get(b);
		return Utils.byteArrayToInt(b);
	}

	static byte[] deserializeData(ByteBuffer buff) {
		int len = deserializeDataLen(buff);

		byte[] b = new byte[len];
		buff.get(b);
		return b;
	}

	static byte[] deserializeMac(ByteBuffer buff) {
		byte[] b = new byte[DataLength.MAC];
		buff.get(b);
		return b;
	}

	static BigInteger deserializeMpi(ByteBuffer buff) {
		int len = deserializeDataLen(buff);

		byte[] b = new byte[len];
		buff.get(b);

		// MPIs must use the minimum-length encoding; i.e. no leading 0x00
		// bytes.
		byte[] bTrimmed = Utils.trim(b);
		return new BigInteger(1, bTrimmed);
	}

	static int deserializeInt(ByteBuffer buff) {
		byte[] b = new byte[DataLength.INT];
		buff.get(b);
		return Utils.byteArrayToInt(b);
	}

	static byte[] deserializeCtr(ByteBuffer buff) {
		byte[] b = new byte[DataLength.CTR];
		buff.get(b);
		return b;
	}

	static byte[] computeXB(PrivateKey privKey, PublicKey pubKey, int keyidB,
			byte[] MB) throws InvalidKeyException, NoSuchAlgorithmException,
			SignatureException {

		byte[] pubBBytes = serializeDsaPublicKey(pubKey);
		byte[] keyidBBytes = serializeInt(keyidB);
		byte[] sigB = sign(MB, privKey);

		int len = pubBBytes.length + keyidBBytes.length + sigB.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(pubBBytes);
		buff.put(keyidBBytes);
		buff.put(sigB);
		return buff.array();
	}

	static byte[] computeMB(DHPublicKey gxKey, DHPublicKey gyKey, int keyidB,
			PublicKey pubB, byte[] m1) throws InvalidKeyException,
			NoSuchAlgorithmException {

		byte[] gx = serializeDHPublicKey(gxKey);
		byte[] gy = serializeDHPublicKey(gyKey);
		byte[] keyidBytes = serializeInt(keyidB);
		byte[] pub = serializeDsaPublicKey(pubB);

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
