package net.java.otr4j.message.encoded;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import net.java.otr4j.Utils;
import net.java.otr4j.crypto.CryptoConstants;

public class DeserializationUtils {

	public static PublicKey readPublicKey(ByteArrayInputStream in)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			IOException {

		int type = DeserializationUtils.readShort(in);
		switch (type) {
		case CryptoConstants.DSA_PUB_TYPE:
			BigInteger p = DeserializationUtils.readMpi(in);
			BigInteger q = DeserializationUtils.readMpi(in);
			BigInteger g = DeserializationUtils.readMpi(in);
			BigInteger y = DeserializationUtils.readMpi(in);
			DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			return keyFactory.generatePublic(keySpec);
		default:
			throw new UnsupportedOperationException();
		}

	}

	public static int readShort(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[DataLength.SHORT];
		in.read(b);
		return Utils.byteArrayToInt(b);
	}

	public static int readByte(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[DataLength.BYTE];
		in.read(b);
		return Utils.byteArrayToInt(b);
	}

	static int readDataLen(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[DataLength.DATALEN];
		in.read(b);
		return Utils.byteArrayToInt(b);
	}

	public static byte[] readData(ByteArrayInputStream in) throws IOException {
		int len = readDataLen(in);

		byte[] b = new byte[len];
		in.read(b);
		return b;
	}

	public static byte[] readMac(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[DataLength.MAC];
		in.read(b);
		return b;
	}

	static BigInteger readMpi(ByteArrayInputStream in) throws IOException {
		int len = readDataLen(in);

		byte[] b = new byte[len];
		in.read(b);

		// MPIs must use the minimum-length encoding; i.e. no leading 0x00
		// bytes.
		byte[] bTrimmed = Utils.trim(b);
		return new BigInteger(1, bTrimmed);
	}

	public static int readInt(java.io.ByteArrayInputStream stream)
			throws IOException {
		byte[] b = new byte[DataLength.INT];
		stream.read(b);
		return Utils.byteArrayToInt(b);
	}

	public static byte[] readCtr(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[DataLength.CTR];
		in.read(b);
		return b;
	}

	public static BigInteger[] readSignature(java.io.ByteArrayInputStream stream) {
		throw new UnsupportedOperationException("Not implemented");
	}

}
