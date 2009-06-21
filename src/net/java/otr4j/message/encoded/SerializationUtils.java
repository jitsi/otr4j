package net.java.otr4j.message.encoded;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import net.java.otr4j.Utils;
import net.java.otr4j.crypto.CryptoConstants;

public class SerializationUtils {

	public static void writeShort(java.io.ByteArrayOutputStream stream, int n)
			throws IOException {
		stream.write(Utils.intToByteArray(n, DataLength.SHORT));
	}

	public static void writeByte(java.io.ByteArrayOutputStream stream, int n)
			throws IOException {
		stream.write(Utils.intToByteArray(n, DataLength.BYTE));
	}

	public static void writeInt(java.io.ByteArrayOutputStream stream, int n)
			throws IOException {
		stream.write(Utils.intToByteArray(n, DataLength.INT));
	}

	public static void writeData(java.io.ByteArrayOutputStream stream, byte[] b)
			throws IOException {
		stream.write(Utils.intToByteArray(b.length, DataLength.DATALEN));
		stream.write(b);
	}

	public static void writeMpi(java.io.ByteArrayOutputStream stream,
			BigInteger i) throws IOException {
		writeData(stream, i.toByteArray());
	}

	public static void writePublicKey(java.io.ByteArrayOutputStream stream,
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

	public static void writeSignature(java.io.ByteArrayOutputStream stream,
			BigInteger[] signatureRS) throws IOException {
		// TODO verify that this is correct.
		stream.write(signatureRS[0].toByteArray());
		stream.write(signatureRS[1].toByteArray());
	}

}
