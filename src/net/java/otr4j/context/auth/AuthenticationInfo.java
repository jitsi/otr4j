package net.java.otr4j.context.auth;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import org.apache.log4j.Logger;

import net.java.otr4j.AuthenticationState;
import net.java.otr4j.Utils;
import net.java.otr4j.crypto.CryptoConstants;
import net.java.otr4j.crypto.CryptoUtils;

public class AuthenticationInfo {

	private static Logger logger = Logger.getLogger(AuthenticationInfo.class);

	public AuthenticationState authenticationState;
	public byte[] r;

	public DHPublicKey theirDHPublicKey;
	public byte[] theirDHPublicKeyEncrypted;
	public byte[] theirDHPublicKeyHash;

	public KeyPair ourDHKeyPair;
	public int ourDHPrivateKeyID;
	public byte[] ourDHPublicKeyHash;
	public byte[] ourDHPublicKeyEncrypted;

	public BigInteger s;
	public byte[] c;
	public byte[] m1;
	public byte[] m2;
	public byte[] cp;
	public byte[] m1p;
	public byte[] m2p;

	public byte[] ourM;
	public byte[] ourX;
	public byte[] ourXEncrypted;
	public byte[] ourXMac;

	public byte[] m;
	public byte[] x;
	public byte[] xEncrypted;
	public byte[] xMac;

	public PublicKey ourLongTermPublicKey;
	public PrivateKey ourLongTermPrivateKey;

	public void initialize() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		this.authenticationState = AuthenticationState.NONE;
		
		logger.debug("Picking random key r.");
		this.r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);

		logger.debug("Generating own D-H key pair.");
		this.ourDHKeyPair = CryptoUtils.generateDHKeyPair();
		this.ourDHPrivateKeyID = 1;

		byte[] gx = ((DHPublicKey) ourDHKeyPair.getPublic()).getY()
				.toByteArray();

		logger.debug("Hashing gx");
		this.ourDHPublicKeyHash = CryptoUtils.sha256Hash(gx);

		logger.debug("Encrypting gx");
		this.ourDHPublicKeyEncrypted = CryptoUtils.aesEncrypt(r, gx);
	}
}
