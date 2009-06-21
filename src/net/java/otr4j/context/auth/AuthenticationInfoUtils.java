package net.java.otr4j.context.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import net.java.otr4j.crypto.CryptoConstants;
import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.encoded.SerializationUtils;

public class AuthenticationInfoUtils {
	private static byte[] h2(byte b, BigInteger s)
			throws NoSuchAlgorithmException, IOException {
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		SerializationUtils.writeMpi(bos, s);

		byte[] secbytes = bos.toByteArray();
		int len = secbytes.length + 1;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(b);
		buff.put(secbytes);
		return CryptoUtils.sha256Hash(buff.array());
	}

	public static byte[] getSSID(BigInteger s) throws NoSuchAlgorithmException, IOException {
		byte[] h2 = h2(CryptoConstants.SSID_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);

		byte[] ssid = new byte[CryptoConstants.SSID_LENGTH];
		buff.get(ssid);
		return ssid;
	}

	public static byte[] getC(BigInteger s) throws NoSuchAlgorithmException, IOException {
		byte[] h2 = h2(CryptoConstants.C_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] c = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		buff.get(c);
		return c;
	}

	public static byte[] getCp(BigInteger s) throws NoSuchAlgorithmException, IOException {
		byte[] h2 = h2(CryptoConstants.C_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] cp = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		buff.position(CryptoConstants.AES_KEY_BYTE_LENGTH);
		buff.get(cp);
		return cp;
	}

	public static byte[] getM1(BigInteger s) throws NoSuchAlgorithmException, IOException {
		byte[] h2 = h2(CryptoConstants.M1_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}

	public static byte[] getM1p(BigInteger s) throws NoSuchAlgorithmException, IOException {
		byte[] h2 = h2(CryptoConstants.M1p_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}

	public static byte[] getM2(BigInteger s) throws NoSuchAlgorithmException, IOException {
		byte[] h2 = h2(CryptoConstants.M2_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}

	public static byte[] getM2p(BigInteger s) throws NoSuchAlgorithmException,
			IOException {
		byte[] h2 = h2(CryptoConstants.M2p_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		return m1;
	}
}
