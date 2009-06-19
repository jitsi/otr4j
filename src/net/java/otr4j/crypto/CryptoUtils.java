package net.java.otr4j.crypto;

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
import java.security.spec.InvalidKeySpecException;
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

public class CryptoUtils {

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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

	public static DHPublicKey getDHPublicKey(byte[] mpiBytes)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return getDHPublicKey(new BigInteger(mpiBytes));
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

	public static byte[] sha256Hmac(byte[] b, byte[] key)
			throws InvalidKeyException, NoSuchAlgorithmException {
		return CryptoUtils.sha256Hmac(b, key, 0);
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

	public static byte[] aesDecrypt(byte[] key, byte[] b)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		// Create cipher KeySpec based on r.
		SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
		// Create initial counter value 0.
		IvParameterSpec spec = new IvParameterSpec(CryptoConstants.ZERO_CTR);

		// Initialize cipher.
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, keyspec, spec);

		return cipher.doFinal(b);
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

	public static BigInteger generateSecret(PrivateKey privKey, PublicKey pubKey)
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(privKey);
		ka.doPhase(pubKey, true);
		BigInteger s = new BigInteger(ka.generateSecret());
		return s;
	}
}
