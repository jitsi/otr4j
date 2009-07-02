package net.java.otr4j.crypto;

import java.math.*;
import java.nio.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.*;

public class CryptoUtils {

	static {
		Security
				.addProvider(new BouncyCastleProvider());
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

	public static byte[] sha1Hmac(byte[] b, byte[] key, int length)
			throws NoSuchAlgorithmException, InvalidKeyException {

		SecretKeySpec keyspec = new SecretKeySpec(key, "HmacSHA1");
		javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
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

	public static byte[] sha1Hash(byte[] b) throws NoSuchAlgorithmException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-1");
		sha256.update(b, 0, b.length);
		return sha256.digest();
	}

	public static byte[] aesDecrypt(byte[] key, byte[] ctr, byte[] b)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		// Create cipher KeySpec based on r.
		SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
		// Create initial counter value 0.
		if (ctr == null)
			ctr = CryptoConstants.ZERO_CTR;
		IvParameterSpec spec = new IvParameterSpec(ctr);

		// Initialize cipher.
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, keyspec, spec);

		return cipher.doFinal(b);
	}

	public static byte[] aesEncrypt(byte[] key, byte[] ctr, byte[] b)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {

		// Create cipher KeySpec based on r.
		SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
		// Create initial counter value 0.
		if (ctr == null)
			ctr = CryptoConstants.ZERO_CTR;
		IvParameterSpec spec = new IvParameterSpec(ctr);

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

	public static byte[] sign(byte[] b, PrivateKey privatekey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {

		if (!(privatekey instanceof DSAPrivateKey))
			throw new IllegalArgumentException();

		Signature signer = Signature.getInstance(privatekey.getAlgorithm());
		signer.initSign(privatekey);
		signer.update(b);
		return signer.sign();
	}

	public static Boolean verify(byte[] b, PublicKey pubKey, byte[] signature)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new IllegalArgumentException();

		Signature signer = Signature.getInstance(pubKey.getAlgorithm());
		signer.initVerify(pubKey);
		signer.update(b);
		return (signer.verify(signature));
	}
}
