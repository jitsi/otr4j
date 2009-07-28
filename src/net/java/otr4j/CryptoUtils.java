/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j;

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
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.util.BigIntegers;

/**
 * 
 * @author George Politis
 * 
 */
public class CryptoUtils implements CryptoConstants {

	public static KeyPair generateDsaKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
		return kg.genKeyPair();
	}

	public static KeyPair generateDHKeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException {

		// Generate a AsymmetricCipherKeyPair using BC.
		DHParameters dhParams = new DHParameters(MODULUS, GENERATOR, null,
				DH_PRIVATE_KEY_MINIMUM_BIT_LENGTH);
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

		DHPublicKeySpec pubKeySpecs = new DHPublicKeySpec(pub.getY(), MODULUS,
				GENERATOR);
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
		DHPublicKeySpec pubKeySpecs = new DHPublicKeySpec(mpi, MODULUS,
				GENERATOR);

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
			throws OtrException {

		AESFastEngine aesDec = new AESFastEngine();
		SICBlockCipher sicAesDec = new SICBlockCipher(aesDec);
		BufferedBlockCipher bufSicAesDec = new BufferedBlockCipher(sicAesDec);

		// Create initial counter value 0.
		if (ctr == null)
			ctr = ZERO_CTR;
		bufSicAesDec.init(false, new ParametersWithIV(new KeyParameter(key),
				ctr));
		byte[] aesOutLwDec = new byte[b.length];
		int done = bufSicAesDec.processBytes(b, 0, b.length, aesOutLwDec, 0);
		try {
			bufSicAesDec.doFinal(aesOutLwDec, done);
		} catch (Exception e) {
			throw new OtrException(e);
		}

		return aesOutLwDec;
	}

	public static byte[] aesEncrypt(byte[] key, byte[] ctr, byte[] b)
			throws OtrException {

		AESFastEngine aesEnc = new AESFastEngine();
		SICBlockCipher sicAesEnc = new SICBlockCipher(aesEnc);
		BufferedBlockCipher bufSicAesEnc = new BufferedBlockCipher(sicAesEnc);

		// Create initial counter value 0.
		if (ctr == null)
			ctr = ZERO_CTR;
		bufSicAesEnc.init(true,
				new ParametersWithIV(new KeyParameter(key), ctr));
		byte[] aesOutLwEnc = new byte[b.length];
		int done = bufSicAesEnc.processBytes(b, 0, b.length, aesOutLwEnc, 0);
		try {
			bufSicAesEnc.doFinal(aesOutLwEnc, done);
		} catch (Exception e) {
			throw new OtrException(e);
		}
		return aesOutLwEnc;
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

		DSAParams dsaParams = ((DSAPrivateKey) privatekey).getParams();
		DSAParameters bcDSAParameters = new DSAParameters(dsaParams.getP(),
				dsaParams.getQ(), dsaParams.getG());

		DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privatekey;
		DSAPrivateKeyParameters bcDSAPrivateKeyParms = new DSAPrivateKeyParameters(
				dsaPrivateKey.getX(), bcDSAParameters);

		DSASigner dsaSigner = new DSASigner();
		dsaSigner.init(true, bcDSAPrivateKeyParms);

		BigInteger q = dsaParams.getQ();

		// Ian: Note that if you can get the standard DSA implementation you're
		// using to not hash its input, you should be able to pass it ((256-bit
		// value) mod q), (rather than truncating the 256-bit value) and all
		// should be well.
		// ref: Interop problems with libotr - DSA signature
		BigInteger bmpi = new BigInteger(1, b);
		BigInteger[] rs = dsaSigner.generateSignature(BigIntegers
				.asUnsignedByteArray(bmpi.mod(q)));

		int siglen = q.bitLength() / 4;
		int rslen = siglen / 2;
		byte[] rb = BigIntegers.asUnsignedByteArray(rs[0]);
		byte[] sb = BigIntegers.asUnsignedByteArray(rs[1]);

		// Create the final signature array, padded with zeros if necessary.
		byte[] sig = new byte[siglen];
		Boolean writeR = false;
		Boolean writeS = false;
		for (int i = 0; i < siglen; i++) {
			if (i < rslen) {
				if (!writeR)
					writeR = rb.length >= rslen - i;
				sig[i] = (writeR) ? rb[i] : (byte) 0x0;
			} else {
				int j = i - rslen; // Rebase.
				if (!writeS)
					writeS = sb.length >= rslen - j;
				sig[i] = (writeS) ? sb[j] : (byte) 0x0;
			}
		}
		return sig;
	}

	public static Boolean verify(byte[] b, PublicKey pubKey, byte[] rs)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new IllegalArgumentException();

		DSAParams dsaParams = ((DSAPublicKey) pubKey).getParams();
		int qlen = dsaParams.getQ().bitLength() / 8;
		ByteBuffer buff = ByteBuffer.wrap(rs);
		byte[] r = new byte[qlen];
		buff.get(r);
		byte[] s = new byte[qlen];
		buff.get(s);
		return verify(b, pubKey, r, s);
	}

	private static Boolean verify(byte[] b, PublicKey pubKey, byte[] r, byte[] s)
			throws InvalidKeyException, NoSuchAlgorithmException,
			SignatureException {
		Boolean result = verify(b, pubKey, new BigInteger(1, r),
				new BigInteger(1, s));
		return result;
	}

	private static Boolean verify(byte[] b, PublicKey pubKey, BigInteger r,
			BigInteger s) throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {

		if (!(pubKey instanceof DSAPublicKey))
			throw new IllegalArgumentException();

		DSAParams dsaParams = ((DSAPublicKey) pubKey).getParams();

		BigInteger q = dsaParams.getQ();
		DSAParameters bcDSAParams = new DSAParameters(dsaParams.getP(), q,
				dsaParams.getG());

		DSAPublicKey dsaPrivateKey = (DSAPublicKey) pubKey;
		DSAPublicKeyParameters dsaPrivParms = new DSAPublicKeyParameters(
				dsaPrivateKey.getY(), bcDSAParams);

		// Ian: Note that if you can get the standard DSA implementation you're
		// using to not hash its input, you should be able to pass it ((256-bit
		// value) mod q), (rather than truncating the 256-bit value) and all
		// should be well.
		// ref: Interop problems with libotr - DSA signature
		DSASigner dsaSigner = new DSASigner();
		dsaSigner.init(false, dsaPrivParms);

		BigInteger bmpi = new BigInteger(1, b);
		Boolean result = dsaSigner.verifySignature(BigIntegers
				.asUnsignedByteArray(bmpi.mod(q)), r, s);
		return result;
	}
}
