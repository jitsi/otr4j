package net.java.otr4j.message.encoded;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.asn1.*;

import net.java.otr4j.Utils;
import net.java.otr4j.crypto.CryptoConstants;
import net.java.otr4j.crypto.CryptoUtils;

public class DeserializationUtils {

	public static PublicKey readPublicKey(ByteArrayInputStream in)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			IOException {

		int type = DeserializationUtils.readShort(in);
		switch (type) {
		case CryptoConstants.DSA_PUB_TYPE:
			BigInteger p = DeserializationUtils.readMpi(in, null);
			BigInteger q = DeserializationUtils.readMpi(in, null);
			BigInteger g = DeserializationUtils.readMpi(in, null);
			BigInteger y = DeserializationUtils.readMpi(in, null);
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

	static int readDataLen(ByteArrayInputStream in, ByteArrayOutputStream out)
			throws IOException {
		byte[] b = new byte[DataLength.DATALEN];
		in.read(b);
		if (out != null)
			out.write(b);
		return Utils.byteArrayToInt(b);
	}

	public static byte[] readData(ByteArrayInputStream in,
			ByteArrayOutputStream out) throws IOException {
		int len = readDataLen(in, null);

		byte[] b = new byte[len];
		in.read(b);
		if (out != null)
			out.write(b);
		return b;
	}

	public static byte[] readMac(ByteArrayInputStream in) throws IOException {
		byte[] b = new byte[DataLength.MAC];
		in.read(b);
		return b;
	}

	static BigInteger readMpi(ByteArrayInputStream in, ByteArrayOutputStream out)
			throws IOException {
		int len = readDataLen(in, out);

		byte[] b = new byte[len];
		in.read(b);
		if (out != null)
			out.write(b);

		return new BigInteger(1, Utils.trim(b));
	}

	public static int readInt(java.io.ByteArrayInputStream stream,
			ByteArrayOutputStream out) throws IOException {
		byte[] b = new byte[DataLength.INT];
		stream.read(b);
		if (out != null)
			out.write(b);

		return Utils.byteArrayToInt(b);
	}

	public static byte[] readCtr(ByteArrayInputStream in,
			ByteArrayOutputStream out) throws IOException {
		byte[] b = new byte[DataLength.CTR];
		in.read(b);
		if (out != null)
			out.write(b);
		return b;
	}

	public static byte[] readSignature(java.io.ByteArrayInputStream stream,
			PublicKey pubKey) throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();

		DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
		DSAParams dsaParams = dsaPubKey.getParams();
		int qlen = dsaParams.getQ().bitLength() / 8;
		// http://www.codeproject.com/KB/security/CryptoInteropSign.aspx
		// http://java.sun.com/j2se/1.4.2/docs/guide/security/CryptoSpec.html

		byte[] r = new byte[qlen];
		byte[] s = new byte[qlen];

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DERSequenceGenerator seqGen = new DERSequenceGenerator(bos);

		stream.read(r);
		seqGen.addObject(new DERInteger(new BigInteger(1, r)));
		stream.read(s);
		seqGen.addObject(new DERInteger(new BigInteger(1, s)));
		seqGen.close();

		return bos.toByteArray();
	}

	public static byte[] readData(ByteArrayInputStream stream)
			throws IOException {
		return readData(stream, null);
	}

	public static DHPublicKey readDHPublicKey(ByteArrayInputStream stream)
			throws IOException {
		return readDHPublicKey(stream, null);
	}

	public static int readInt(java.io.ByteArrayInputStream stream)
			throws IOException {
		return readInt(stream, null);
	}

	public static byte[] readCtr(ByteArrayInputStream stream)
			throws IOException {
		return readCtr(stream, null);
	}

	static DHPublicKey readDHPublicKey(ByteArrayInputStream in,
			ByteArrayOutputStream out) throws IOException {
		BigInteger gyMpi = DeserializationUtils.readMpi(in, out);
		try {
			return CryptoUtils.getDHPublicKey(gyMpi);
		} catch (Exception ex) {
			throw new IOException(ex);
		}
	}
}
