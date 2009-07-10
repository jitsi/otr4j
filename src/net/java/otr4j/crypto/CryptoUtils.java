package net.java.otr4j.crypto;

import java.math.*;
import java.nio.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.*;
import org.bouncycastle.util.BigIntegers;

public class CryptoUtils {

	public static KeyPair generateDsaKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
		return kg.genKeyPair();
	}

	public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException {

		// Generate a AsymmetricCipherKeyPair using BC.
		DHParameters dhParams = new DHParameters(CryptoConstants.MODULUS,
				CryptoConstants.GENERATOR, null,
				CryptoConstants.DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH);
		DHKeyGenerationParameters params = new DHKeyGenerationParameters(
				new SecureRandom(), dhParams);
		DHKeyPairGenerator kpGen = new DHKeyPairGenerator();

		kpGen.init(params);
		AsymmetricCipherKeyPair pair = kpGen.generateKeyPair();

		// Convert this AsymmetricCipherKeyPair to a standard JCE KeyPair.
		DHPublicKeyParameters pub = (DHPublicKeyParameters) pair.getPublic();
		DHPrivateKeyParameters priv = (DHPrivateKeyParameters) pair
				.getPrivate();

		KeyFactory keyFac = KeyFactory.getInstance("DH");

		DHPublicKeySpec pubKeySpecs = new DHPublicKeySpec(pub.getY(),
				CryptoConstants.MODULUS, CryptoConstants.GENERATOR);
		DHPublicKey pubKey = (DHPublicKey) keyFac.generatePublic(pubKeySpecs);

		DHParameters dhParameters = priv.getParameters();
		DHPrivateKeySpec privKeySpecs = new DHPrivateKeySpec(priv.getX(),
				dhParameters.getP(), dhParameters.getG());
		DHPrivateKey privKey = (DHPrivateKey) keyFac
				.generatePrivate(privKeySpecs);

		return new KeyPair(pubKey, privKey);
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
		byte[] sb = ka.generateSecret();
		BigInteger s = new BigInteger(1, sb);
		return s;
	}

	public static byte[] sign(byte[] b, PrivateKey privatekey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {

		if (!(privatekey instanceof DSAPrivateKey))
			throw new IllegalArgumentException();

		/*
		 * Signature signer = Signature.getInstance(privatekey.getAlgorithm());
		 * signer.initSign(privatekey); signer.update(b); return signer.sign();
		 */

		// construct the BC objects from pub key specs
		DSAParams dsaParams = ((DSAPrivateKey) privatekey).getParams();
		DSAParameters bcDSAParams = new DSAParameters(dsaParams.getP(),
				dsaParams.getQ(), dsaParams.getG());

		DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privatekey;
		DSAPrivateKeyParameters dsaPrivParms = new DSAPrivateKeyParameters(
				dsaPrivateKey.getX(), bcDSAParams);

		// and now do the signature verification
		DSASigner dsaSigner = new DSASigner();
		dsaSigner.init(true, dsaPrivParms);

		BigInteger[] rs = dsaSigner.generateSignature(b);
		byte[] rb = BigIntegers.asUnsignedByteArray(rs[0]);
		byte[] sb = BigIntegers.asUnsignedByteArray(rs[1]);
		ByteBuffer buff = ByteBuffer.allocate(rb.length + sb.length);
		buff.put(rb);
		buff.put(sb);
		return buff.array();
	}

	public static Boolean verify(byte[] b, PublicKey pubKey, byte[] signature)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new IllegalArgumentException();

		Signature signer = Signature.getInstance(pubKey.getAlgorithm());
		signer.initVerify(pubKey);
		signer.update(b);
		return signer.verify(signature);
	}
}
