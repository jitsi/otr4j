package net.java.otr4j.context.auth;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import org.apache.log4j.Logger;

import net.java.otr4j.Utils;
import net.java.otr4j.crypto.CryptoConstants;
import net.java.otr4j.crypto.CryptoUtils;

public class AuthenticationInfo {

	private static Logger logger = Logger.getLogger(AuthenticationInfo.class);

	public AuthenticationInfo() {
		this.authenticationState = AuthenticationState.NONE;
	}

	public AuthenticationState authenticationState;
	public byte[] r;

	public DHPublicKey remoteDHPublicKey;
	public byte[] remoteDHPublicKeyEncrypted;
	public byte[] remoteDHPublicKeyHash;

	public KeyPair localDHKeyPair;
	public int localDHPrivateKeyID;
	public byte[] localDHPublicKeyHash;
	public byte[] localDHPublicKeyEncrypted;

	public BigInteger s;
	public byte[] c;
	public byte[] m1;
	public byte[] m2;
	public byte[] cp;
	public byte[] m1p;
	public byte[] m2p;

	public byte[] localXEncrypted;
	public byte[] localXEncryptedMac;

	public KeyPair localLongTermKeyPair;

	public void initialize() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		this.authenticationState = AuthenticationState.NONE;

		logger.debug("Picking random key r.");
		this.r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);

		logger.debug("Generating own D-H key pair.");
		this.localDHKeyPair = CryptoUtils.generateDHKeyPair();
		this.localDHPrivateKeyID = 1;

		byte[] gx = ((DHPublicKey) localDHKeyPair.getPublic()).getY()
				.toByteArray();

		logger.debug("Hashing gx");
		this.localDHPublicKeyHash = CryptoUtils.sha256Hash(gx);

		logger.debug("Encrypting gx");
		this.localDHPublicKeyEncrypted = CryptoUtils.aesEncrypt(r, gx);
	}
}
