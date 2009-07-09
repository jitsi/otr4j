package net.java.otr4j.message.encoded;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.interfaces.*;
/* import java.util.*; */

import javax.crypto.interfaces.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.*;
import net.java.otr4j.*;
import net.java.otr4j.crypto.*;

public class SerializationUtils {

	public static void writeShort(ByteArrayOutputStream stream, int n)
			throws IOException {
		stream.write(Utils.intToByteArray(n, DataLength.SHORT));
	}

	public static void writeByte(ByteArrayOutputStream stream, int n)
			throws IOException {
		stream.write(Utils.intToByteArray(n, DataLength.BYTE));
	}

	public static void writeInt(ByteArrayOutputStream stream, int n)
			throws IOException {
		stream.write(Utils.intToByteArray(n, DataLength.INT));
	}

	public static void writeData(ByteArrayOutputStream stream, byte[] b)
			throws IOException {
		stream.write(Utils.intToByteArray(b.length, DataLength.DATALEN));
		stream.write(b);
	}

	public static void writeDHPublicKey(ByteArrayOutputStream stream,
			DHPublicKey pubKey) throws IOException {
		byte[] b = BigIntegers.asUnsignedByteArray(pubKey.getY());
		writeData(stream, b);
	}

	public static void writeMpi(ByteArrayOutputStream stream, BigInteger i)
			throws IOException {
		byte[] b = BigIntegers.asUnsignedByteArray(i);
		writeData(stream, b);
	}

	public static void writePublicKey(ByteArrayOutputStream stream,
			PublicKey pubKey) throws InvalidKeyException, IOException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new UnsupportedOperationException(
					"Key types other than DSA are not supported at the moment.");

		DSAPublicKey dsaKey = (DSAPublicKey) pubKey;

		writeShort(stream, CryptoConstants.DSA_PUB_TYPE);

		DSAParams dsaParams = dsaKey.getParams();
		writeMpi(stream, dsaParams.getP());
		writeMpi(stream, dsaParams.getQ());
		writeMpi(stream, dsaParams.getG());
		writeMpi(stream, dsaKey.getY());
	}

	public static void writeSignature(ByteArrayOutputStream stream,
			byte[] signature, PublicKey pubKey) throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();

		// http://www.codeproject.com/KB/security/CryptoInteropSign.aspx
		// http://java.sun.com/j2se/1.4.2/docs/guide/security/CryptoSpec.html

		DERSequence derSequence = null;
		try {
			derSequence = (DERSequence) DERSequence.fromByteArray(signature);
		} catch (Exception ex) {
			throw new IOException(ex);
		}
		DERInteger r = (DERInteger) derSequence.getObjectAt(0);
		DERInteger s = (DERInteger) derSequence.getObjectAt(1);

		byte[] rb = BigIntegers.asUnsignedByteArray(r.getValue());
		byte[] sb = BigIntegers.asUnsignedByteArray(s.getValue());

		stream.write(rb);
		stream.write(sb);
	}

	public static void writeMac(ByteArrayOutputStream stream, byte[] mac)
			throws IOException {
		if (mac == null || mac.length != DataLength.MAC)
			throw new IllegalArgumentException();

		stream.write(mac);
	}

	public static void writeCtr(ByteArrayOutputStream out, byte[] ctr)
			throws IOException {
		out.write(java.util.Arrays.copyOfRange(ctr, 0, DataLength.CTR));
	}

}
