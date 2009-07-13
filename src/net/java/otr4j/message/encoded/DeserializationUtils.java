package net.java.otr4j.message.encoded;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.interfaces.*;
import net.java.otr4j.*;
import net.java.otr4j.crypto.*;

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

	public static BigInteger readMpi(ByteArrayInputStream in) throws IOException {
		int len = readDataLen(in);

		byte[] b = new byte[len];
		in.read(b);
		return new BigInteger(1, b);
	}

	public static int readInt(ByteArrayInputStream stream) throws IOException {
		byte[] b = new byte[DataLength.INT];
		stream.read(b);
		return Utils.byteArrayToInt(b);
	}

	public static byte[] readCtr(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[DataLength.CTR];
		in.read(b);
		return b;
	}

	public static byte[] readSignature(ByteArrayInputStream stream,
			PublicKey pubKey) throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();

		DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
		DSAParams dsaParams = dsaPubKey.getParams();
		byte[] sig = new byte[dsaParams.getQ().bitLength() / 4];
		stream.read(sig);
		return sig;
	}

	static DHPublicKey readDHPublicKey(ByteArrayInputStream in)
			throws IOException {
		BigInteger gyMpi = DeserializationUtils.readMpi(in);
		try {
			return CryptoUtils.getDHPublicKey(gyMpi);
		} catch (Exception ex) {
			throw new IOException(ex);
		}
	}
}
