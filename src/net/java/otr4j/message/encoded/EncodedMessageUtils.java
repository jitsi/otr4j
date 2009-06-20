package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import net.java.otr4j.MysteriousM;
import net.java.otr4j.Utils;
import net.java.otr4j.crypto.CryptoConstants;
import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.MessageHeader;
import org.apache.commons.codec.binary.Base64;

public final class EncodedMessageUtils {

	public static byte[] decodeMessage(String msg) {
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

	public static byte[] serializeShort(int n) {
		return Utils.intToByteArray(n, DataLength.SHORT);
	}

	public static byte[] serializeByte(int n) {
		return Utils.intToByteArray(n, DataLength.BYTE);
	}

	public static byte[] serializeInt(int n) {
		return Utils.intToByteArray(n, DataLength.INT);
	}

	public static byte[] serializeData(byte[] b) {
		byte[] len = Utils.intToByteArray(b.length, DataLength.DATALEN);

		ByteBuffer buff = ByteBuffer.allocate(b.length + len.length);
		buff.put(len);
		buff.put(b);
		return buff.array();
	}

	public static byte[] serializeMpi(BigInteger i) {
		return serializeData(i.toByteArray());
	}

	public static PublicKey deserializeDsaPublicKey(ByteBuffer buff)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		deserializeShort(buff);
		BigInteger p = deserializeMpi(buff);
		BigInteger q = deserializeMpi(buff);
		BigInteger g = deserializeMpi(buff);
		BigInteger y = deserializeMpi(buff);
		DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
		KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		return keyFactory.generatePublic(keySpec);
	}

	public static byte[] serializePublicKey(PublicKey pubKey)
			throws InvalidKeyException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new UnsupportedOperationException();

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
		return Utils.byteArrayToInt(b);
	}

	public static int deserializeByte(ByteBuffer buff) {
		byte[] b = new byte[DataLength.BYTE];
		buff.get(b);
		return Utils.byteArrayToInt(b);
	}

	private static int deserializeDataLen(ByteBuffer buff) {
		byte[] b = new byte[DataLength.DATALEN];
		buff.get(b);
		return Utils.byteArrayToInt(b);
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

	static BigInteger deserializeMpi(ByteBuffer buff) {
		int len = deserializeDataLen(buff);

		byte[] b = new byte[len];
		buff.get(b);

		// MPIs must use the minimum-length encoding; i.e. no leading 0x00
		// bytes.
		byte[] bTrimmed = Utils.trim(b);
		return new BigInteger(1, bTrimmed);
	}

	public static int deserializeInt(ByteBuffer buff) {
		byte[] b = new byte[DataLength.INT];
		buff.get(b);
		return Utils.byteArrayToInt(b);
	}

	public static byte[] deserializeCtr(ByteBuffer buff) {
		byte[] b = new byte[DataLength.CTR];
		buff.get(b);
		return b;
	}

	public static byte[] serializeM(MysteriousM m) throws InvalidKeyException,
			NoSuchAlgorithmException {
		byte[] gxSerialized = EncodedMessageUtils.serializeMpi(m.ourDHPublicKey
				.getY());
		byte[] gySerialized = EncodedMessageUtils
				.serializeMpi(m.theirDHPublicKey.getY());
		byte[] pubKeySerialized = EncodedMessageUtils
				.serializePublicKey(m.ourLongTermPublicKey);
		byte[] keyidSerialized = EncodedMessageUtils
				.serializeInt(m.ourDHPrivatecKeyID);

		int len = gxSerialized.length + gySerialized.length
				+ pubKeySerialized.length + keyidSerialized.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(gxSerialized);
		buff.put(gySerialized);
		buff.put(pubKeySerialized);
		buff.put(keyidSerialized);

		return CryptoUtils.sha256Hmac(buff.array(), m.m1);
	}
}
