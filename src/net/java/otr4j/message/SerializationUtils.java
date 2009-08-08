/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.CryptoConstants;
import net.java.otr4j.CryptoUtils;
import net.java.otr4j.OtrException;

import org.bouncycastle.util.BigIntegers;

/**
 * 
 * @author George Politis
 */
public class SerializationUtils implements SerializationConstants {

	private static byte[] intToByteArray(int value, int length) {
		byte[] b = new byte[length];
		for (int i = 0; i < length; i++) {
			int offset = (b.length - 1 - i) * 8;
			b[i] = (byte) ((value >>> offset) & 0xFF);
		}
		return b;
	}

	public static void writeShort(OutputStream out, int n) throws IOException {
		out.write(intToByteArray(n, SHORT));
	}

	public static void writeByte(OutputStream out, int n) throws IOException {
		out.write(intToByteArray(n, BYTE));
	}

	public static void writeInt(OutputStream out, int n) throws IOException {
		out.write(intToByteArray(n, INT));
	}

	public static void writeTlvData(OutputStream out, byte[] b)
			throws IOException {
		if (b == null || b.length < 0) {
			out.write(intToByteArray(0, TLVDATALEN));
		} else {
			out.write(intToByteArray(b.length, TLVDATALEN));
			out.write(b);
		}
	}

	public static void writeData(OutputStream out, byte[] b) throws IOException {
		if (b == null || b.length < 0) {
			out.write(intToByteArray(0, DATALEN));
		} else {
			out.write(intToByteArray(b.length, DATALEN));
			out.write(b);
		}
	}

	public static byte[] toByteArray(byte[] b) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		SerializationUtils.writeData(out, b);
		byte[] tmp = out.toByteArray();
		out.close();
		return tmp;
	}

	public static void writeDHPublicKey(OutputStream out, DHPublicKey pubKey)
			throws IOException {
		byte[] b = BigIntegers.asUnsignedByteArray(pubKey.getY());
		writeData(out, b);
	}

	public static void writeMpi(OutputStream out, BigInteger i)
			throws IOException {
		byte[] b = BigIntegers.asUnsignedByteArray(i);
		writeData(out, b);
	}

	public static void writePublicKey(OutputStream out, PublicKey pubKey)
			throws IOException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new UnsupportedOperationException(
					"Key types other than DSA are not supported at the moment.");

		DSAPublicKey dsaKey = (DSAPublicKey) pubKey;

		writeShort(out, CryptoConstants.DSA_PUB_TYPE);

		DSAParams dsaParams = dsaKey.getParams();
		writeMpi(out, dsaParams.getP());
		writeMpi(out, dsaParams.getQ());
		writeMpi(out, dsaParams.getG());
		writeMpi(out, dsaKey.getY());
	}

	public static void writeSignature(OutputStream out, byte[] signature,
			PublicKey pubKey) throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();
		out.write(signature);
	}

	public static void writeMac(OutputStream out, byte[] mac)
			throws IOException {
		if (mac == null || mac.length != MAC)
			throw new IllegalArgumentException();

		out.write(mac);
	}

	public static void writeCtr(OutputStream out, byte[] ctr)
			throws IOException {
		out.write(java.util.Arrays.copyOfRange(ctr, 0, CTR));
	}

	public static void writePublicKeyFingerPrint(OutputStream bos,
			PublicKey pubKey) throws IOException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new UnsupportedOperationException(
					"Key types other than DSA are not supported at the moment.");

		writeShort(bos, CryptoConstants.DSA_PUB_TYPE);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		DSAPublicKey dsaKey = (DSAPublicKey) pubKey;
		DSAParams dsaParams = dsaKey.getParams();
		writeMpi(out, dsaParams.getP());
		writeMpi(out, dsaParams.getQ());
		writeMpi(out, dsaParams.getG());
		writeMpi(out, dsaKey.getY());
		byte[] b = out.toByteArray();
		out.close();

		try {
			byte[] fingerprint = CryptoUtils.sha1Hash(b);
			writeData(bos, fingerprint);
		} catch (OtrException e) {
			throw new IOException(e);
		}
	}

	private static int byteArrayToInt(byte[] b) {
		int value = 0;
		for (int i = 0; i < b.length; i++) {
			int shift = (b.length - 1 - i) * 8;
			value += (b[i] & 0x000000FF) << shift;
		}
		return value;
	}

	public static PublicKey readPublicKey(InputStream in) throws IOException {

		int type = readShort(in);
		switch (type) {
		case CryptoConstants.DSA_PUB_TYPE:
			BigInteger p = readMpi(in);
			BigInteger q = readMpi(in);
			BigInteger g = readMpi(in);
			BigInteger y = readMpi(in);
			DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
			KeyFactory keyFactory;
			try {
				keyFactory = KeyFactory.getInstance("DSA");
			} catch (NoSuchAlgorithmException e) {
				throw new IOException(e);
			}
			try {
				return keyFactory.generatePublic(keySpec);
			} catch (InvalidKeySpecException e) {
				throw new IOException(e);
			}
		default:
			throw new UnsupportedOperationException();
		}

	}

	public static int readShort(InputStream in) throws IOException {
		byte[] b = new byte[SHORT];
		in.read(b);
		return byteArrayToInt(b);
	}

	public static int readByte(InputStream in) throws IOException {
		byte[] b = new byte[BYTE];
		in.read(b);
		return byteArrayToInt(b);
	}

	static int readDataLen(InputStream in) throws IOException {
		byte[] b = new byte[DATALEN];
		in.read(b);
		return byteArrayToInt(b);
	}

	static int readTlvDataLen(InputStream in) throws IOException {
		byte[] b = new byte[TLVDATALEN];
		in.read(b);
		return byteArrayToInt(b);
	}

	public static byte[] readData(InputStream in) throws IOException {
		int len = readDataLen(in);

		byte[] b = new byte[len];
		in.read(b);
		return b;
	}

	public static byte[] readTlvData(InputStream in) throws IOException {
		int len = readTlvDataLen(in);

		byte[] b = new byte[len];
		in.read(b);
		return b;
	}

	public static byte[] readMac(InputStream in) throws IOException {
		byte[] b = new byte[MAC];
		in.read(b);
		return b;
	}

	public static BigInteger readMpi(InputStream in) throws IOException {
		int len = readDataLen(in);

		byte[] b = new byte[len];
		in.read(b);
		return new BigInteger(1, b);
	}

	public static int readInt(InputStream in) throws IOException {
		byte[] b = new byte[INT];
		in.read(b);
		return byteArrayToInt(b);
	}

	public static byte[] readCtr(InputStream in) throws IOException {
		byte[] b = new byte[CTR];
		in.read(b);
		return b;
	}

	public static byte[] readSignature(InputStream in, PublicKey pubKey)
			throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();

		DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
		DSAParams dsaParams = dsaPubKey.getParams();
		byte[] sig = new byte[dsaParams.getQ().bitLength() / 4];
		in.read(sig);
		return sig;
	}

	public static DHPublicKey readDHPublicKey(InputStream in)
			throws IOException {
		BigInteger gyMpi = readMpi(in);
		try {
			return CryptoUtils.getDHPublicKey(gyMpi);
		} catch (Exception ex) {
			throw new IOException(ex);
		}
	}
}
