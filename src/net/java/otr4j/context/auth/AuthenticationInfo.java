package net.java.otr4j.context.auth;

import java.io.IOException;
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
		this.setAuthenticationState(AuthenticationState.NONE);
	}

	private AuthenticationState authenticationState;
	private byte[] r;

	private DHPublicKey remoteDHPublicKey;
	private int remoteDHPPublicKeyID;
	private byte[] remoteDHPublicKeyEncrypted;
	private byte[] remoteDHPublicKeyHash;

	private KeyPair localDHKeyPair;
	private int localDHPrivateKeyID;
	private byte[] localDHPublicKeyHash;
	private byte[] localDHPublicKeyEncrypted;

	private BigInteger s;
	private byte[] c;
	private byte[] m1;
	private byte[] m2;
	private byte[] cp;
	private byte[] m1p;
	private byte[] m2p;

	private byte[] localXEncrypted;
	private byte[] localXEncryptedMac;

	private KeyPair localLongTermKeyPair;

	public void initialize() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException {
		this.setAuthenticationState(AuthenticationState.NONE);

		logger.debug("Picking random key r.");
		this.setR(Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH));

		logger.debug("Generating own D-H key pair.");
		this.setLocalDHKeyPair(CryptoUtils.generateDHKeyPair());
		
		logger.debug("Setting our keyID to 1.");
		this.setLocalDHPrivateKeyID(1);

		byte[] gx = ((DHPublicKey) getLocalDHKeyPair().getPublic()).getY()
				.toByteArray();

		logger.debug("Hashing gx");
		this.setLocalDHPublicKeyHash(CryptoUtils.sha256Hash(gx));

		logger.debug("Encrypting gx");
		this.setLocalDHPublicKeyEncrypted(CryptoUtils.aesEncrypt(getR(), gx));
	}

	public void setAuthenticationState(AuthenticationState authenticationState) {
		this.authenticationState = authenticationState;
	}

	public AuthenticationState getAuthenticationState() {
		return authenticationState;
	}

	public void setR(byte[] r) {
		this.r = r;
	}

	public byte[] getR() {
		return r;
	}

	public void setRemoteDHPublicKey(DHPublicKey remoteDHPublicKey) {
		this.remoteDHPublicKey = remoteDHPublicKey;
	}

	public DHPublicKey getRemoteDHPublicKey() {
		return remoteDHPublicKey;
	}

	public void setRemoteDHPublicKeyEncrypted(
			byte[] remoteDHPublicKeyEncrypted) {
		this.remoteDHPublicKeyEncrypted = remoteDHPublicKeyEncrypted;
	}

	public byte[] getRemoteDHPublicKeyEncrypted() {
		return remoteDHPublicKeyEncrypted;
	}

	public void setRemoteDHPublicKeyHash(byte[] remoteDHPublicKeyHash) {
		this.remoteDHPublicKeyHash = remoteDHPublicKeyHash;
	}

	public byte[] getRemoteDHPublicKeyHash() {
		return remoteDHPublicKeyHash;
	}

	public void setLocalDHKeyPair(KeyPair localDHKeyPair) {
		this.localDHKeyPair = localDHKeyPair;
	}

	public KeyPair getLocalDHKeyPair() {
		return localDHKeyPair;
	}

	public void setLocalDHPrivateKeyID(int localDHPrivateKeyID) {
		this.localDHPrivateKeyID = localDHPrivateKeyID;
	}

	public int getLocalDHPrivateKeyID() {
		return localDHPrivateKeyID;
	}

	public void setLocalDHPublicKeyHash(byte[] localDHPublicKeyHash) {
		this.localDHPublicKeyHash = localDHPublicKeyHash;
	}

	public byte[] getLocalDHPublicKeyHash() {
		return localDHPublicKeyHash;
	}

	public void setLocalDHPublicKeyEncrypted(byte[] localDHPublicKeyEncrypted) {
		this.localDHPublicKeyEncrypted = localDHPublicKeyEncrypted;
	}

	public byte[] getLocalDHPublicKeyEncrypted() {
		return localDHPublicKeyEncrypted;
	}

	public void setS(BigInteger s) throws NoSuchAlgorithmException, IOException {
		this.s = s;
		this.setC(AuthenticationInfoUtils.getC(s));
		this.setCp(AuthenticationInfoUtils.getCp(s));
		this.setM1(AuthenticationInfoUtils.getM1(s));
		this.setM1p(AuthenticationInfoUtils.getM1p(s));
		this.setM2(AuthenticationInfoUtils.getM2(s));
		this.setM2p(AuthenticationInfoUtils.getM2p(s));
	}

	public BigInteger getS() {
		return s;
	}

	private void setC(byte[] c) {
		this.c = c;
	}

	public byte[] getC() {
		return c;
	}

	private void setM1(byte[] m1) {
		this.m1 = m1;
	}

	public byte[] getM1() {
		return m1;
	}

	private void setM2(byte[] m2) {
		this.m2 = m2;
	}

	public byte[] getM2() {
		return m2;
	}

	private void setCp(byte[] cp) {
		this.cp = cp;
	}

	public byte[] getCp() {
		return cp;
	}

	private void setM1p(byte[] m1p) {
		this.m1p = m1p;
	}

	public byte[] getM1p() {
		return m1p;
	}

	private void setM2p(byte[] m2p) {
		this.m2p = m2p;
	}

	public byte[] getM2p() {
		return m2p;
	}

	public void setLocalXEncrypted(byte[] localXEncrypted) {
		this.localXEncrypted = localXEncrypted;
	}

	public byte[] getLocalXEncrypted() {
		return localXEncrypted;
	}

	public void setLocalXEncryptedMac(byte[] localXEncryptedMac) {
		this.localXEncryptedMac = localXEncryptedMac;
	}

	public byte[] getLocalXEncryptedMac() {
		return localXEncryptedMac;
	}

	public void setLocalLongTermKeyPair(KeyPair localLongTermKeyPair) {
		this.localLongTermKeyPair = localLongTermKeyPair;
	}

	public KeyPair getLocalLongTermKeyPair() {
		return localLongTermKeyPair;
	}

	public void setRemoteDHPPublicKeyID(int remoteDHPPublicKeyID) {
		this.remoteDHPPublicKeyID = remoteDHPPublicKeyID;
	}

	public int getRemoteDHPPublicKeyID() {
		return remoteDHPPublicKeyID;
	}
}
