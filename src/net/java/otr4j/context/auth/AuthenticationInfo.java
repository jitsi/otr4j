package net.java.otr4j.context.auth;

import java.io.*;
import java.math.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays; /* This needs to be done explicitly due to conflicting name */
import java.util.logging.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;

import net.java.otr4j.*;
import net.java.otr4j.crypto.*;
import net.java.otr4j.message.encoded.*;
import net.java.otr4j.message.encoded.signature.RevealSignatureMessage;
import net.java.otr4j.message.encoded.signature.SignatureMessage;

public class AuthenticationInfo {

	private static Logger logger = Logger.getLogger(AuthenticationInfo.class
			.getName());

	public AuthenticationInfo() {
		this.reset();
	}

	private AuthenticationState authenticationState;
	private byte[] r;

	private DHPublicKey remoteDHPublicKey;
	private int remoteDHPPublicKeyID;
	private byte[] remoteDHPublicKeyEncrypted;
	private byte[] remoteDHPublicKeyHash;

	private KeyPair localDHKeyPair;
	private int localDHPrivateKeyID;
	private byte[] localDHPublicKeyBytes;
	private byte[] localDHPublicKeyHash;
	private byte[] localDHPublicKeyEncrypted;

	private BigInteger s;
	private byte[] c;
	private byte[] m1;
	private byte[] m2;
	private byte[] cp;
	private byte[] m1p;
	private byte[] m2p;

	private KeyPair localLongTermKeyPair;

	public void setAuthAwaitingDHKey() {
		this.setAuthenticationState(AuthenticationState.AWAITING_DHKEY);
	}

	public DHCommitMessage getDHCommitMessage() throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, IOException {
		return new DHCommitMessage(2, this.getLocalDHPublicKeyHash(), this
				.getLocalDHPublicKeyEncrypted());
	}

	public DHKeyMessage getDHKeyMessage() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException {
		return new DHKeyMessage(2, (DHPublicKey) this.getLocalDHKeyPair()
				.getPublic());
	}

	public void setAuthAwaitingRevealSig(DHCommitMessage dhCommitMessage) {
		this.setRemoteDHPublicKeyEncrypted(dhCommitMessage
				.getDhPublicKeyEncrypted());
		this.setRemoteDHPublicKeyHash(dhCommitMessage.getDhPublicKeyHash());
		this.setAuthenticationState(AuthenticationState.AWAITING_REVEALSIG);
	}

	public RevealSignatureMessage getRevealSignatureMessage()
			throws InvalidKeyException, NoSuchAlgorithmException,
			SignatureException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, IOException {
		MysteriousX x = this.getLocalMysteriousX(false);
		return new RevealSignatureMessage(2, this.getR(), x.hash, x.encrypted);
	}

	public void setAuthAwaitingSig(DHKeyMessage dhKeyMessage,
			KeyPair localLongTermKeypair) {
		this.setLocalLongTermKeyPair(localLongTermKeypair);
		this.setRemoteDHPublicKey(dhKeyMessage.getDhPublicKey());
		this.setAuthenticationState(AuthenticationState.AWAITING_SIG);
	}

	public void goSecure(RevealSignatureMessage revealSigMessage,
			KeyPair localLongTerm) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException, IOException,
			NoSuchProviderException, OtrException, SignatureException {
		this.setRemoteDHPublicKey(revealSigMessage.getRevealedKey());

		// Verify received Data.
		if (!revealSigMessage.verify(this.getM2()))
			throw new OtrException(
					"Signature MACs are not equal, ignoring message.");

		// Decrypt X.
		byte[] remoteXDecrypted = revealSigMessage.decrypt(this.getC());
		MysteriousX remoteX = new MysteriousX();
		remoteX.readObject(remoteXDecrypted);

		// Compute signature.
		MysteriousM remoteM = new MysteriousM(this.getRemoteDHPublicKey(),
				(DHPublicKey) this.getLocalDHKeyPair().getPublic(), remoteX
						.getLongTermPublicKey(), remoteX.getDhKeyID());

		// Verify signature.
		if (!remoteM.verify(this.getM1(), remoteX.getLongTermPublicKey(),
				remoteX.getSignature()))
			throw new OtrException("Signature verification failed.");

		logger.info("Signature verification succeeded.");

		// Compute our own signature.
		this.setLocalLongTermKeyPair(localLongTerm);

		// Compute X.

		// Go secure, this must be done after X has been calculated.
		this.setRemoteDHPublicKeyID(remoteX.getDhKeyID());
	}

	public SignatureMessage getSignatureMessage() throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		MysteriousX x = this.getLocalMysteriousX(true);
		return new SignatureMessage(2, x.hash, x.encrypted);
	}

	public void goSecure(SignatureMessage signatureMessage)
			throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, IOException, OtrException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, SignatureException {
		// Verify MAC.
		if (!signatureMessage.verify(this.getM2p()))
			throw new OtrException(
					"Signature MACs are not equal, ignoring message.");

		// Decrypt X.
		byte[] remoteXDecrypted = signatureMessage.decrypt(this.getCp());
		MysteriousX remoteX = new MysteriousX();
		remoteX.readObject(remoteXDecrypted);

		// Compute signature.
		MysteriousM remoteM = new MysteriousM(this.getRemoteDHPublicKey(),
				(DHPublicKey) this.getLocalDHKeyPair().getPublic(), remoteX
						.getLongTermPublicKey(), remoteX.getDhKeyID());

		// Verify signature.
		if (!remoteM.verify(this.getM1p(), remoteX.getLongTermPublicKey(),
				remoteX.getSignature()))
			throw new OtrException("Signature verification failed.");

		this.setRemoteDHPublicKeyID(remoteX.getDhKeyID());
	}

	public void reset() {
		logger.info("Resetting authentication state.");
		authenticationState = AuthenticationState.NONE;
		r = null;

		remoteDHPublicKey = null;
		remoteDHPPublicKeyID = -1;
		remoteDHPublicKeyEncrypted = null;
		remoteDHPublicKeyHash = null;

		localDHKeyPair = null;
		localDHPrivateKeyID = 1;
		localDHPublicKeyBytes = null;
		localDHPublicKeyHash = null;
		localDHPublicKeyEncrypted = null;

		s = null;
		c = m1 = m2 = cp = m1p = m2p = null;

		mysteriousX = null;

		localLongTermKeyPair = null;
	}

	private void setAuthenticationState(AuthenticationState authenticationState) {
		this.authenticationState = authenticationState;
	}

	public AuthenticationState getAuthenticationState() {
		return authenticationState;
	}

	public byte[] getR() {
		if (r == null) {
			logger.info("Picking random key r.");
			r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);
		}
		return r;
	}

	public void setRemoteDHPublicKey(DHPublicKey dhPublicKey) {
		// Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)
		if (dhPublicKey.getY().compareTo(CryptoConstants.MODULUS_MINUS_TWO) > 0) {
			throw new IllegalArgumentException(
					"Illegal D-H Public Key value, Ignoring message.");
		} else if (dhPublicKey.getY().compareTo(CryptoConstants.BIGINTEGER_TWO) < 0) {
			throw new IllegalArgumentException(
					"Illegal D-H Public Key value, Ignoring message.");
		}
		logger.info("Received D-H Public Key is a legal value.");

		this.remoteDHPublicKey = dhPublicKey;
	}

	public void setRemoteDHPublicKey(byte[] revealedKey)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException,
			InvalidKeySpecException {
		// Uses r to decrypt the value of gx sent earlier
		byte[] remoteDHPublicKeyDecrypted = CryptoUtils.aesDecrypt(revealedKey,
				null, this.getRemoteDHPublicKeyEncrypted());

		// Verifies that HASH(gx) matches the value sent earlier
		byte[] remoteDHPublicKeyHash = CryptoUtils
				.sha256Hash(remoteDHPublicKeyDecrypted);
		if (!Arrays.equals(remoteDHPublicKeyHash, this
				.getRemoteDHPublicKeyHash())) {
			throw new IllegalArgumentException(
					"Hashes don't match, ignoring message.");
		}

		// Verifies that Bob's gx is a legal value (2 <= gx <= modulus-2)
		ByteArrayInputStream inmpi = new ByteArrayInputStream(
				remoteDHPublicKeyDecrypted);
		BigInteger remoteDHPublicKeyMpi = DeserializationUtils.readMpi(inmpi);

		this.setRemoteDHPublicKey(CryptoUtils
				.getDHPublicKey(remoteDHPublicKeyMpi));
	}

	public DHPublicKey getRemoteDHPublicKey() {
		return remoteDHPublicKey;
	}

	public void setRemoteDHPublicKeyEncrypted(byte[] remoteDHPublicKeyEncrypted) {
		logger.info("Storing encrypted remote public key.");
		this.remoteDHPublicKeyEncrypted = remoteDHPublicKeyEncrypted;
	}

	public byte[] getRemoteDHPublicKeyEncrypted() {
		return remoteDHPublicKeyEncrypted;
	}

	public void setRemoteDHPublicKeyHash(byte[] remoteDHPublicKeyHash) {
		logger.info("Storing encrypted remote public key hash.");
		this.remoteDHPublicKeyHash = remoteDHPublicKeyHash;
	}

	public byte[] getRemoteDHPublicKeyHash() {
		return remoteDHPublicKeyHash;
	}

	public KeyPair getLocalDHKeyPair() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException {
		if (localDHKeyPair == null) {
			localDHKeyPair = CryptoUtils.generateDHKeyPair();
			logger.info("Generated local D-H key pair.");
		}
		return localDHKeyPair;
	}

	public int getLocalDHKeyPairID() {
		return localDHPrivateKeyID;
	}

	public byte[] getLocalDHPublicKeyHash() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, IOException {
		if (localDHPublicKeyHash == null) {
			localDHPublicKeyHash = CryptoUtils
					.sha256Hash(getLocalDHPublicKeyBytes());
			logger.info("Hashed local D-H public key.");
		}
		return localDHPublicKeyHash;
	}

	public byte[] getLocalDHPublicKeyEncrypted() throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException,
			InvalidKeySpecException, IOException {
		if (localDHPublicKeyEncrypted == null) {
			localDHPublicKeyEncrypted = CryptoUtils.aesEncrypt(getR(), null,
					getLocalDHPublicKeyBytes());
			logger.info("Encrypted our D-H public key.");
		}
		return localDHPublicKeyEncrypted;
	}

	public BigInteger getS() throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException {
		if (s == null) {
			s = CryptoUtils.generateSecret(this.getLocalDHKeyPair()
					.getPrivate(), this.getRemoteDHPublicKey());
			logger.info("Generated shared secret.");
		}
		return s;
	}

	public byte[] getC() throws NoSuchAlgorithmException, IOException {
		if (c != null)
			return c;

		byte[] h2 = h2(CryptoConstants.C_START, s);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		this.c = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		buff.get(this.c);
		logger.info("Computed c.");
		return c;

	}

	public byte[] getM1() throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException {
		if (m1 != null)
			return m1;

		byte[] h2 = h2(CryptoConstants.M1_START, this.getS());
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		logger.info("Computed m1.");
		this.m1 = m1;
		return m1;
	}

	public byte[] getM2() throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException {
		if (m2 != null)
			return m2;

		byte[] h2 = h2(CryptoConstants.M2_START, this.getS());
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m2 = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m2);
		logger.info("Computed m2.");
		this.m2 = m2;
		return m2;
	}

	public byte[] getCp() throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException {
		if (cp != null)
			return cp;

		byte[] h2 = h2(CryptoConstants.C_START, this.getS());
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] cp = new byte[CryptoConstants.AES_KEY_BYTE_LENGTH];
		buff.position(CryptoConstants.AES_KEY_BYTE_LENGTH);
		buff.get(cp);
		logger.info("Computed c'.");
		this.cp = cp;
		return cp;
	}

	public byte[] getM1p() throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException {
		if (m1p != null)
			return m1p;

		byte[] h2 = h2(CryptoConstants.M1p_START, this.getS());
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1p = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1p);
		this.m1p = m1p;
		logger.info("Computed m1'.");
		return m1p;
	}

	public byte[] getM2p() throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException {
		if (m2p != null)
			return m2p;

		byte[] h2 = h2(CryptoConstants.M2p_START, this.getS());
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m2p = new byte[CryptoConstants.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m2p);
		this.m2p = m2p;
		logger.info("Computed m2'.");
		return m2p;
	}

	private MysteriousX mysteriousX;

	private Boolean pSet;

	public MysteriousX getLocalMysteriousX(Boolean pSet)
			throws InvalidKeyException, NoSuchAlgorithmException,
			SignatureException, InvalidAlgorithmParameterException,
			NoSuchProviderException, InvalidKeySpecException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException {

		if (this.mysteriousX == null || (this.pSet != pSet)) {
			DHPublicKey ourDHPublicKey = (DHPublicKey) this.getLocalDHKeyPair()
					.getPublic();
			MysteriousM m = new MysteriousM(ourDHPublicKey, this
					.getRemoteDHPublicKey(), this.getLocalLongTermKeyPair()
					.getPublic(), this.getLocalDHKeyPairID());

			byte[] signatureHashKey = (pSet) ? this.getM1p() : this.getM1();
			byte[] xEncryptionKey = (pSet) ? this.getCp() : this.getC();
			byte[] xHashKey = (pSet) ? this.getM2p() : this.getM2();

			byte[] signature = m.sign(signatureHashKey, this
					.getLocalLongTermKeyPair().getPrivate());

			// Computes XB = pubB, keyidB, sigB(MB)
			logger.info("Computing X");
			this.mysteriousX = new MysteriousX(this.getLocalLongTermKeyPair()
					.getPublic(), this.getLocalDHKeyPairID(), signature);
			this.mysteriousX.update(xEncryptionKey, xHashKey);
		}
		return this.mysteriousX;
	}

	public void setLocalLongTermKeyPair(KeyPair localLongTermKeyPair) {
		this.localLongTermKeyPair = localLongTermKeyPair;
	}

	public KeyPair getLocalLongTermKeyPair() {
		return localLongTermKeyPair;
	}

	public void setRemoteDHPublicKeyID(int remoteDHPPublicKeyID) {
		this.remoteDHPPublicKeyID = remoteDHPPublicKeyID;
	}

	public int getRemoteDHPPublicKeyID() {
		return remoteDHPPublicKeyID;
	}

	private static byte[] h2(byte b, BigInteger s)
			throws NoSuchAlgorithmException, IOException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		SerializationUtils.writeMpi(bos, s);
		byte[] secbytes = bos.toByteArray();
		bos.close();

		int len = secbytes.length + 1;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(b);
		buff.put(secbytes);
		byte[] sdata = buff.array();
		return CryptoUtils.sha256Hash(sdata);
	}

	public byte[] getLocalDHPublicKeyBytes() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException, IOException {
		if (localDHPublicKeyBytes == null) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			SerializationUtils.writeMpi(out, ((DHPublicKey) getLocalDHKeyPair()
					.getPublic()).getY());
			this.localDHPublicKeyBytes = out.toByteArray();
		}
		return localDHPublicKeyBytes;
	}
}
