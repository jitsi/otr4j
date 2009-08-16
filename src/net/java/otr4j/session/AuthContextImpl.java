/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.session;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Logger;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.OtrEngineHost;
import net.java.otr4j.OtrException;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.message.DHCommitMessage;
import net.java.otr4j.message.DHKeyMessage;
import net.java.otr4j.message.MessageConstants;
import net.java.otr4j.message.MessageUtils;
import net.java.otr4j.message.RevealSignatureMessage;
import net.java.otr4j.message.SerializationUtils;
import net.java.otr4j.message.SignatureMessage;

/**
 * 
 * @author George Politis
 */
class AuthContextImpl implements AuthContext {

	/**
	 * 
	 * @author George Politis
	 */
	public class MysteriousX {

		public MysteriousX() {

		}

		public MysteriousX(PublicKey ourLongTermPublicKey, int ourKeyID,
				byte[] signature) {
			this.setDhKeyID(ourKeyID);
			this.setLongTermPublicKey(ourLongTermPublicKey);
			this.setSignature(signature);
		}

		public void readObject(byte[] b) throws IOException {
			ByteArrayInputStream bis = null;
			try {
				bis = new ByteArrayInputStream(b);
				this.readObject(bis);
			} catch (Exception e) {
				bis.close();
			}
		}

		public void readObject(java.io.ByteArrayInputStream stream)
				throws IOException {
			try {
				this.setLongTermPublicKey(SerializationUtils
						.readPublicKey(stream));
			} catch (Exception e) {
				throw new IOException(e);
			}
			this.setDhKeyID(SerializationUtils.readInt(stream));
			this.setSignature(SerializationUtils.readSignature(stream, this
					.getLongTermPublicKey()));
		}

		private PublicKey longTermPublicKey;
		private int dhKeyID;
		private byte[] signature;

		public void writeObject(java.io.ByteArrayOutputStream stream)
				throws IOException {

			try {
				SerializationUtils.writePublicKey(stream, this
						.getLongTermPublicKey());
			} catch (Exception e) {
				throw new IOException(e);
			}
			SerializationUtils.writeInt(stream, this.getDhKeyID());
			SerializationUtils.writeSignature(stream, this.getSignature(), this
					.getLongTermPublicKey());
		}

		public byte[] toByteArray() throws IOException {
			ByteArrayOutputStream out = null;
			byte[] bosArray = null;
			try {
				out = new ByteArrayOutputStream();
				this.writeObject(out);
				bosArray = out.toByteArray();
			} finally {
				if (out != null)
					out.close();
			}

			return bosArray;
		}

		public void setLongTermPublicKey(PublicKey longTermPublicKey) {
			this.longTermPublicKey = longTermPublicKey;
		}

		public PublicKey getLongTermPublicKey() {
			return longTermPublicKey;
		}

		public void setDhKeyID(int dhKeyID) {
			this.dhKeyID = dhKeyID;
		}

		public int getDhKeyID() {
			return dhKeyID;
		}

		public void setSignature(byte[] signature) {
			this.signature = signature;
		}

		public byte[] getSignature() {
			return signature;
		}
	}

	/**
	 * 
	 * @author George Politis
	 */
	public class MysteriousM {

		public MysteriousM(DHPublicKey ourDHPublicKey,
				DHPublicKey theirDHPublicKey, PublicKey ourLongTermPublicKey,
				int ourDHPrivateKeyID) {

			this.setOurDHPublicKey(ourDHPublicKey);
			this.setTheirDHPublicKey(theirDHPublicKey);
			this.setOurLongTermPublicKey(ourLongTermPublicKey);
			this.setOurDHPrivatecKeyID(ourDHPrivateKeyID);
		}

		private DHPublicKey ourDHPublicKey;
		private DHPublicKey theirDHPublicKey;
		private PublicKey ourLongTermPublicKey;
		private int ourDHPrivatecKeyID;

		public void writeObject(OutputStream out) throws IOException {
			SerializationUtils.writeMpi(out, this.getOurDHPublicKey().getY());
			SerializationUtils.writeMpi(out, this.getTheirDHPublicKey().getY());
			SerializationUtils.writePublicKey(out, this
					.getOurLongTermPublicKey());

			SerializationUtils.writeInt(out, this.getOurDHPrivatecKeyID());
		}

		public byte[] toByteArray() throws IOException {
			ByteArrayOutputStream out = null;
			byte[] bosArray = null;
			try {
				out = new ByteArrayOutputStream();
				this.writeObject(out);
				bosArray = out.toByteArray();
			} finally {
				if (out != null)
					out.close();
			}

			return bosArray;
		}

		public void setOurDHPublicKey(DHPublicKey ourDHPublicKey) {
			this.ourDHPublicKey = ourDHPublicKey;
		}

		public DHPublicKey getOurDHPublicKey() {
			return ourDHPublicKey;
		}

		public void setTheirDHPublicKey(DHPublicKey theirDHPublicKey) {
			this.theirDHPublicKey = theirDHPublicKey;
		}

		public DHPublicKey getTheirDHPublicKey() {
			return theirDHPublicKey;
		}

		public void setOurLongTermPublicKey(PublicKey ourLongTermPublicKey) {
			this.ourLongTermPublicKey = ourLongTermPublicKey;
		}

		public PublicKey getOurLongTermPublicKey() {
			return ourLongTermPublicKey;
		}

		public void setOurDHPrivatecKeyID(int ourDHPrivatecKeyID) {
			this.ourDHPrivatecKeyID = ourDHPrivatecKeyID;
		}

		public int getOurDHPrivatecKeyID() {
			return ourDHPrivatecKeyID;
		}
	}

	public AuthContextImpl(SessionID sessionID, OtrEngineHost listener) {
		this.setSessionID(sessionID);
		this.setListener(listener);
		this.reset();
	}

	private SessionID sessionID;
	private OtrEngineHost listener;

	private int authenticationState;
	private byte[] r;

	private DHPublicKey remoteDHPublicKey;
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
	private Boolean isSecure = false;
	private int protocolVersion;

	private int getProtocolVersion() {
		return this.protocolVersion;
	}

	private void setProtocolVersion(int protoVersion) {
		this.protocolVersion = protoVersion;
	}

	private static Logger logger = Logger.getLogger(AuthContextImpl.class
			.getName());

	private DHCommitMessage getDHCommitMessage() throws OtrException {
		return new DHCommitMessage(this.getProtocolVersion(), this
				.getLocalDHPublicKeyHash(), this.getLocalDHPublicKeyEncrypted());
	}

	private DHKeyMessage getDHKeyMessage() throws OtrException {
		return new DHKeyMessage(this.getProtocolVersion(), (DHPublicKey) this
				.getLocalDHKeyPair().getPublic());
	}

	private RevealSignatureMessage getRevealSignatureMessage()
			throws OtrException {

		try {
			MysteriousM m = new MysteriousM((DHPublicKey) this
					.getLocalDHKeyPair().getPublic(), this
					.getRemoteDHPublicKey(), this.getLocalLongTermKeyPair()
					.getPublic(), this.getLocalDHKeyPairID());

			OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();
			byte[] mhash = otrCryptoEngine.sha256Hmac(m.toByteArray(), this
					.getM1());
			byte[] signature = otrCryptoEngine.sign(mhash, this
					.getLocalLongTermKeyPair().getPrivate());

			MysteriousX mysteriousX = new MysteriousX(this
					.getLocalLongTermKeyPair().getPublic(), this
					.getLocalDHKeyPairID(), signature);

			byte[] xEncrypted = otrCryptoEngine.aesEncrypt(this.getC(), null,
					mysteriousX.toByteArray());

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			SerializationUtils.writeData(out, xEncrypted);
			byte[] tmp = out.toByteArray();
			out.close();

			byte[] xEncryptedHash = otrCryptoEngine.sha256Hmac160(tmp, this
					.getM2());
			return new RevealSignatureMessage(this.getProtocolVersion(), this
					.getR(), xEncryptedHash, xEncrypted);
		} catch (IOException e) {
			throw new OtrException(e);
		}
	}

	private SignatureMessage getSignatureMessage() throws OtrException {

		MysteriousM m = new MysteriousM((DHPublicKey) this.getLocalDHKeyPair()
				.getPublic(), this.getRemoteDHPublicKey(), this
				.getLocalLongTermKeyPair().getPublic(), this
				.getLocalDHKeyPairID());

		OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();
		byte[] mhash;
		try {
			mhash = otrCryptoEngine.sha256Hmac(m.toByteArray(), this.getM1p());
		} catch (IOException e) {
			throw new OtrException(e);
		}
		byte[] signature = otrCryptoEngine.sign(mhash, this
				.getLocalLongTermKeyPair().getPrivate());

		MysteriousX mysteriousX = new MysteriousX(this
				.getLocalLongTermKeyPair().getPublic(), this
				.getLocalDHKeyPairID(), signature);

		byte[] xEncrypted;
		try {
			xEncrypted = otrCryptoEngine.aesEncrypt(this.getCp(), null,
					mysteriousX.toByteArray());

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			SerializationUtils.writeData(out, xEncrypted);
			byte[] tmp = out.toByteArray();
			out.close();

			byte[] xEncryptedHash = otrCryptoEngine.sha256Hmac160(tmp, this
					.getM2p());
			return new SignatureMessage(this.getProtocolVersion(),
					xEncryptedHash, xEncrypted);
		} catch (IOException e) {
			throw new OtrException(e);
		}
	}

	public void reset() {
		logger.info("Resetting authentication state.");
		authenticationState = AuthContext.NONE;
		r = null;

		remoteDHPublicKey = null;
		remoteDHPublicKeyEncrypted = null;
		remoteDHPublicKeyHash = null;

		localDHKeyPair = null;
		localDHPrivateKeyID = 1;
		localDHPublicKeyBytes = null;
		localDHPublicKeyHash = null;
		localDHPublicKeyEncrypted = null;

		s = null;
		c = m1 = m2 = cp = m1p = m2p = null;

		localLongTermKeyPair = null;
		protocolVersion = 0;
		setIsSecure(false);
	}

	private void setIsSecure(Boolean isSecure) {
		this.isSecure = isSecure;
	}

	public boolean getIsSecure() {
		return isSecure;
	}

	private void setAuthenticationState(int authenticationState) {
		this.authenticationState = authenticationState;
	}

	private int getAuthenticationState() {
		return authenticationState;
	}

	private byte[] getR() {
		if (r == null) {
			logger.info("Picking random key r.");
			r = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
			new Random().nextBytes(r);
		}
		return r;
	}

	private void setRemoteDHPublicKey(DHPublicKey dhPublicKey) {
		// Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)
		if (dhPublicKey.getY().compareTo(OtrCryptoEngine.MODULUS_MINUS_TWO) > 0) {
			throw new IllegalArgumentException(
					"Illegal D-H Public Key value, Ignoring message.");
		} else if (dhPublicKey.getY().compareTo(OtrCryptoEngine.BIGINTEGER_TWO) < 0) {
			throw new IllegalArgumentException(
					"Illegal D-H Public Key value, Ignoring message.");
		}
		logger.info("Received D-H Public Key is a legal value.");

		this.remoteDHPublicKey = dhPublicKey;
	}

	public DHPublicKey getRemoteDHPublicKey() {
		return remoteDHPublicKey;
	}

	private void setRemoteDHPublicKeyEncrypted(byte[] remoteDHPublicKeyEncrypted) {
		logger.info("Storing encrypted remote public key.");
		this.remoteDHPublicKeyEncrypted = remoteDHPublicKeyEncrypted;
	}

	private byte[] getRemoteDHPublicKeyEncrypted() {
		return remoteDHPublicKeyEncrypted;
	}

	private void setRemoteDHPublicKeyHash(byte[] remoteDHPublicKeyHash) {
		logger.info("Storing encrypted remote public key hash.");
		this.remoteDHPublicKeyHash = remoteDHPublicKeyHash;
	}

	private byte[] getRemoteDHPublicKeyHash() {
		return remoteDHPublicKeyHash;
	}

	public KeyPair getLocalDHKeyPair() throws OtrException {
		if (localDHKeyPair == null) {
			localDHKeyPair = new OtrCryptoEngineImpl().generateDHKeyPair();
			logger.info("Generated local D-H key pair.");
		}
		return localDHKeyPair;
	}

	private int getLocalDHKeyPairID() {
		return localDHPrivateKeyID;
	}

	private byte[] getLocalDHPublicKeyHash() throws OtrException {
		if (localDHPublicKeyHash == null) {
			localDHPublicKeyHash = new OtrCryptoEngineImpl()
					.sha256Hash(getLocalDHPublicKeyBytes());
			logger.info("Hashed local D-H public key.");
		}
		return localDHPublicKeyHash;
	}

	private byte[] getLocalDHPublicKeyEncrypted() throws OtrException {
		if (localDHPublicKeyEncrypted == null) {
			localDHPublicKeyEncrypted = new OtrCryptoEngineImpl().aesEncrypt(
					getR(), null, getLocalDHPublicKeyBytes());
			logger.info("Encrypted our D-H public key.");
		}
		return localDHPublicKeyEncrypted;
	}

	public BigInteger getS() throws OtrException {
		if (s == null) {
			s = new OtrCryptoEngineImpl().generateSecret(this
					.getLocalDHKeyPair().getPrivate(), this
					.getRemoteDHPublicKey());
			logger.info("Generated shared secret.");
		}
		return s;
	}

	private byte[] getC() throws OtrException {
		if (c != null)
			return c;

		byte[] h2 = h2(C_START);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		this.c = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
		buff.get(this.c);
		logger.info("Computed c.");
		return c;

	}

	private byte[] getM1() throws OtrException {
		if (m1 != null)
			return m1;

		byte[] h2 = h2(M1_START);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1 = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1);
		logger.info("Computed m1.");
		this.m1 = m1;
		return m1;
	}

	private byte[] getM2() throws OtrException {
		if (m2 != null)
			return m2;

		byte[] h2 = h2(M2_START);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m2 = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m2);
		logger.info("Computed m2.");
		this.m2 = m2;
		return m2;
	}

	private byte[] getCp() throws OtrException {
		if (cp != null)
			return cp;

		byte[] h2 = h2(C_START);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] cp = new byte[OtrCryptoEngine.AES_KEY_BYTE_LENGTH];
		buff.position(OtrCryptoEngine.AES_KEY_BYTE_LENGTH);
		buff.get(cp);
		logger.info("Computed c'.");
		this.cp = cp;
		return cp;
	}

	private byte[] getM1p() throws OtrException {
		if (m1p != null)
			return m1p;

		byte[] h2 = h2(M1p_START);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m1p = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m1p);
		this.m1p = m1p;
		logger.info("Computed m1'.");
		return m1p;
	}

	private byte[] getM2p() throws OtrException {
		if (m2p != null)
			return m2p;

		byte[] h2 = h2(M2p_START);
		ByteBuffer buff = ByteBuffer.wrap(h2);
		byte[] m2p = new byte[OtrCryptoEngine.SHA256_HMAC_KEY_BYTE_LENGTH];
		buff.get(m2p);
		this.m2p = m2p;
		logger.info("Computed m2'.");
		return m2p;
	}

	public KeyPair getLocalLongTermKeyPair() {
		if (localLongTermKeyPair == null) {
			KeyPair pair = getListener().getSessionKeyPair(this.getSessionID());
			if (pair == null) {
				// TODO use built-in management
				try {
					return new OtrCryptoEngineImpl().generateDSAKeyPair();
				} catch (OtrCryptoException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else
				localLongTermKeyPair = pair;
		}
		return localLongTermKeyPair;
	}

	private void setListener(OtrEngineHost listener) {
		this.listener = listener;
	}

	private OtrEngineHost getListener() {
		return listener;
	}

	private byte[] h2(byte b) throws OtrException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		byte[] secbytes;
		try {
			SerializationUtils.writeMpi(bos, getS());
			secbytes = bos.toByteArray();
			bos.close();
		} catch (IOException e) {
			throw new OtrException(e);
		}

		int len = secbytes.length + 1;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(b);
		buff.put(secbytes);
		byte[] sdata = buff.array();
		return new OtrCryptoEngineImpl().sha256Hash(sdata);
	}

	private byte[] getLocalDHPublicKeyBytes() throws OtrException {
		if (localDHPublicKeyBytes == null) {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			try {
				SerializationUtils.writeMpi(out,
						((DHPublicKey) getLocalDHKeyPair().getPublic()).getY());
			} catch (IOException e) {
				throw new OtrException(e);
			}
			this.localDHPublicKeyBytes = out.toByteArray();
		}
		return localDHPublicKeyBytes;
	}

	public void handleReceivingMessage(String msgText) throws OtrException {

		switch (MessageUtils.getMessageType(msgText)) {
		case MessageConstants.DH_COMMIT:
			handleDHCommitMessage(msgText);
			break;
		case MessageConstants.DH_KEY:
			handleDHKeyMessage(msgText);
			break;
		case MessageConstants.REVEALSIG:
			handleRevealSignatureMessage(msgText);
			break;
		case MessageConstants.SIGNATURE:
			handleSignatureMessage(msgText);
			break;
		default:
			throw new UnsupportedOperationException();
		}
	}

	private void handleSignatureMessage(String msgText) throws OtrException {
		logger.info(getSessionID().getAccountID()
				+ " received a signature message from "
				+ getSessionID().getUserID() + " throught "
				+ getSessionID().getProtocolName() + ".");
		if (!getListener().getSessionPolicy(getSessionID()).getAllowV2()) {
			logger.info("Policy does not allow OTRv2, ignoring message.");
			return;
		}

		SignatureMessage sigMessage = new SignatureMessage();
		try {
			sigMessage.readObject(msgText);
		} catch (IOException e) {
			throw new OtrException(e);
		}

		switch (this.getAuthenticationState()) {
		case AWAITING_SIG:
			// Verify MAC.
			if (!sigMessage.verify(this.getM2p())) {
				logger.info("Signature MACs are not equal, ignoring message.");
				return;
			}

			// Decrypt X.
			byte[] remoteXDecrypted = sigMessage.decrypt(this.getCp());
			MysteriousX remoteX = new MysteriousX();
			try {
				remoteX.readObject(remoteXDecrypted);
			} catch (IOException e) {
				throw new OtrException(e);
			}

			// Compute signature.
			PublicKey remoteLongTermPublicKey = remoteX.getLongTermPublicKey();
			MysteriousM remoteM = new MysteriousM(this.getRemoteDHPublicKey(),
					(DHPublicKey) this.getLocalDHKeyPair().getPublic(),
					remoteLongTermPublicKey, remoteX.getDhKeyID());
			OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();
			// Verify signature.
			byte[] signature;
			try {
				signature = otrCryptoEngine.sha256Hmac(remoteM.toByteArray(),
						this.getM1p());
			} catch (IOException e) {
				throw new OtrException(e);
			}
			if (!otrCryptoEngine.verify(signature, remoteLongTermPublicKey,
					remoteX.getSignature())) {
				logger.info("Signature verification failed.");
				return;
			}

			this.setIsSecure(true);
			this.setRemoteLongTermPublicKey(remoteLongTermPublicKey);
			break;
		default:
			logger.info("We were not expecting a signature, ignoring message.");
			return;
		}
	}

	private void handleRevealSignatureMessage(String msgText)
			throws OtrException {

		logger.info(getSessionID().getAccountID()
				+ " received a reveal signature message from "
				+ getSessionID().getUserID() + " throught "
				+ getSessionID().getProtocolName() + ".");

		if (!getListener().getSessionPolicy(getSessionID()).getAllowV2()) {
			logger.info("Policy does not allow OTRv2, ignoring message.");
			return;
		}

		RevealSignatureMessage revealSigMessage = new RevealSignatureMessage();
		try {
			revealSigMessage.readObject(msgText);
		} catch (IOException e) {
			throw new OtrException(e);
		}

		switch (this.getAuthenticationState()) {
		case AWAITING_REVEALSIG:
			// Use the received value of r to decrypt the value of gx
			// received
			// in the D-H Commit Message, and verify the hash therein.
			// Decrypt
			// the encrypted signature, and verify the signature and the
			// MACs.
			// If everything checks out:

			// * Reply with a Signature Message.
			// * Transition authstate to AUTHSTATE_NONE.
			// * Transition msgstate to MSGSTATE_ENCRYPTED.
			// * TODO If there is a recent stored message, encrypt it and
			// send
			// it as a Data Message.

			OtrCryptoEngine otrCryptoEngine = new OtrCryptoEngineImpl();
			// Uses r to decrypt the value of gx sent earlier
			byte[] remoteDHPublicKeyDecrypted = otrCryptoEngine.aesDecrypt(
					revealSigMessage.getRevealedKey(), null, this
							.getRemoteDHPublicKeyEncrypted());

			// Verifies that HASH(gx) matches the value sent earlier
			byte[] remoteDHPublicKeyHash = otrCryptoEngine
					.sha256Hash(remoteDHPublicKeyDecrypted);
			if (!Arrays.equals(remoteDHPublicKeyHash, this
					.getRemoteDHPublicKeyHash())) {
				logger.info("Hashes don't match, ignoring message.");
				return;
			}

			// Verifies that Bob's gx is a legal value (2 <= gx <=
			// modulus-2)
			ByteArrayInputStream inmpi = new ByteArrayInputStream(
					remoteDHPublicKeyDecrypted);
			BigInteger remoteDHPublicKeyMpi;
			try {
				remoteDHPublicKeyMpi = SerializationUtils.readMpi(inmpi);
			} catch (IOException e) {
				throw new OtrException(e);
			}

			this.setRemoteDHPublicKey(otrCryptoEngine
					.getDHPublicKey(remoteDHPublicKeyMpi));

			// Verify received Data.
			if (!revealSigMessage.verify(this.getM2())) {
				logger.info("Signature MACs are not equal, ignoring message.");
				return;
			}

			// Decrypt X.
			byte[] remoteXDecrypted = revealSigMessage.decrypt(this.getC());
			MysteriousX remoteX = new MysteriousX();
			try {
				remoteX.readObject(remoteXDecrypted);
			} catch (IOException e) {
				throw new OtrException(e);
			}

			// Compute signature.
			PublicKey remoteLongTermPublicKey = remoteX.getLongTermPublicKey();
			MysteriousM remoteM = new MysteriousM(this.getRemoteDHPublicKey(),
					(DHPublicKey) this.getLocalDHKeyPair().getPublic(),
					remoteLongTermPublicKey, remoteX.getDhKeyID());

			// Verify signature.
			byte[] signature;
			try {
				signature = otrCryptoEngine.sha256Hmac(remoteM.toByteArray(),
						this.getM1());
			} catch (IOException e) {
				throw new OtrException(e);
			}
			if (!otrCryptoEngine.verify(signature, remoteLongTermPublicKey,
					remoteX.getSignature())) {
				logger.info("Signature verification failed.");
				return;
			}

			logger.info("Signature verification succeeded.");

			this.setAuthenticationState(AuthContext.NONE);
			this.setIsSecure(true);
			this.setRemoteLongTermPublicKey(remoteLongTermPublicKey);
			try {
				getListener().injectMessage(getSessionID(),
						this.getSignatureMessage().writeObject());
			} catch (IOException e) {
				throw new OtrException(e);
			}
			break;
		default:
			logger.info("Ignoring message.");
			break;
		}
	}

	private void handleDHKeyMessage(String msgText) throws OtrException {

		try {
			logger.info(getSessionID().getAccountID()
					+ " received a D-H key message from "
					+ getSessionID().getUserID() + " throught "
					+ getSessionID().getProtocolName() + ".");

			if (!getListener().getSessionPolicy(getSessionID()).getAllowV2()) {
				logger.info("If ALLOW_V2 is not set, ignore this message.");
				return;
			}

			DHKeyMessage dhKey = new DHKeyMessage();
			dhKey.readObject(msgText);

			switch (this.getAuthenticationState()) {
			case AWAITING_DHKEY:
				// Reply with a Reveal Signature Message and transition
				// authstate to
				// AUTHSTATE_AWAITING_SIG
				this.setRemoteDHPublicKey(dhKey.getDhPublicKey());
				this.setAuthenticationState(AuthContext.AWAITING_SIG);
				getListener().injectMessage(getSessionID(),
						this.getRevealSignatureMessage().writeObject());
				logger.info("Sent Reveal Signature.");
				break;
			case AWAITING_SIG:

				if (dhKey.getDhPublicKey().getY().equals(
						this.getRemoteDHPublicKey().getY())) {
					// If this D-H Key message is the same the one you received
					// earlier (when you entered AUTHSTATE_AWAITING_SIG):
					// Retransmit
					// your Reveal Signature Message.
					getListener().injectMessage(getSessionID(),
							this.getRevealSignatureMessage().writeObject());
					logger.info("Resent Reveal Signature.");
				} else {
					// Otherwise: Ignore the message.
					logger.info("Ignoring message.");
				}
				break;
			default:
				// Ignore the message
				break;
			}
		} catch (IOException e) {
			throw new OtrException(e);
		}
	}

	private void handleDHCommitMessage(String msgText) throws OtrException {

		logger.info(getSessionID().getAccountID()
				+ " received a D-H commit message from "
				+ getSessionID().getUserID() + " throught "
				+ getSessionID().getProtocolName() + ".");

		if (!getListener().getSessionPolicy(getSessionID()).getAllowV2()) {
			logger.info("ALLOW_V2 is not set, ignore this message.");
			return;
		}

		DHCommitMessage dhCommit = new DHCommitMessage();
		try {
			dhCommit.readObject(msgText);
		} catch (IOException e) {
			throw new OtrException(e);
		}

		switch (this.getAuthenticationState()) {
		case NONE:
			// Reply with a D-H Key Message, and transition authstate to
			// AUTHSTATE_AWAITING_REVEALSIG.
			this.reset();
			this.setProtocolVersion(2);
			this.setRemoteDHPublicKeyEncrypted(dhCommit
					.getDhPublicKeyEncrypted());
			this.setRemoteDHPublicKeyHash(dhCommit.getDhPublicKeyHash());
			this.setAuthenticationState(AuthContext.AWAITING_REVEALSIG);
			try {
				getListener().injectMessage(getSessionID(),
						this.getDHKeyMessage().writeObject());
			} catch (IOException e) {
				throw new OtrException(e);
			}
			logger.info("Sent D-H key.");
			break;

		case AWAITING_DHKEY:
			// This is the trickiest transition in the whole protocol. It
			// indicates that you have already sent a D-H Commit message to
			// your
			// correspondent, but that he either didn't receive it, or just
			// didn't receive it yet, and has sent you one as well. The
			// symmetry
			// will be broken by comparing the hashed gx you sent in your
			// D-H
			// Commit Message with the one you received, considered as
			// 32-byte
			// unsigned big-endian values.
			BigInteger ourHash = new BigInteger(1, this
					.getLocalDHPublicKeyHash());
			BigInteger theirHash = new BigInteger(1, dhCommit
					.getDhPublicKeyHash());

			if (theirHash.compareTo(ourHash) == -1) {
				// Ignore the incoming D-H Commit message, but resend your
				// D-H
				// Commit message.
				try {
					getListener().injectMessage(getSessionID(),
							this.getDHCommitMessage().writeObject());
				} catch (IOException e) {
					throw new OtrException(e);
				}
				logger
						.info("Ignored the incoming D-H Commit message, but resent our D-H Commit message.");
			} else {
				// *Forget* your old gx value that you sent (encrypted)
				// earlier,
				// and pretend you're in AUTHSTATE_NONE; i.e. reply with a
				// D-H
				// Key Message, and transition authstate to
				// AUTHSTATE_AWAITING_REVEALSIG.
				this.reset();
				this.setProtocolVersion(2);
				this.setRemoteDHPublicKeyEncrypted(dhCommit
						.getDhPublicKeyEncrypted());
				this.setRemoteDHPublicKeyHash(dhCommit.getDhPublicKeyHash());
				this.setAuthenticationState(AuthContext.AWAITING_REVEALSIG);
				try {
					getListener().injectMessage(getSessionID(),
							this.getDHKeyMessage().writeObject());
				} catch (IOException e) {
					throw new OtrException(e);
				}
				logger
						.info("Forgot our old gx value that we sent (encrypted) earlier, and pretended we're in AUTHSTATE_NONE -> Sent D-H key.");
			}
			break;

		case AWAITING_REVEALSIG:
			// Retransmit your D-H Key Message (the same one as you sent
			// when
			// you entered AUTHSTATE_AWAITING_REVEALSIG). Forget the old D-H
			// Commit message, and use this new one instead.
			this.setRemoteDHPublicKeyEncrypted(dhCommit
					.getDhPublicKeyEncrypted());
			this.setRemoteDHPublicKeyHash(dhCommit.getDhPublicKeyHash());
			try {
				getListener().injectMessage(getSessionID(),
						this.getDHKeyMessage().writeObject());
			} catch (IOException e) {
				throw new OtrException(e);
			}
			logger.info("Sent D-H key.");
			break;
		case AWAITING_SIG:
			// Reply with a new D-H Key message, and transition authstate to
			// AUTHSTATE_AWAITING_REVEALSIG
			this.reset();
			this.setRemoteDHPublicKeyEncrypted(dhCommit
					.getDhPublicKeyEncrypted());
			this.setRemoteDHPublicKeyHash(dhCommit.getDhPublicKeyHash());
			this.setAuthenticationState(AuthContext.AWAITING_REVEALSIG);
			try {
				getListener().injectMessage(getSessionID(),
						this.getDHKeyMessage().writeObject());
			} catch (IOException e) {
				throw new OtrException(e);
			}
			logger.info("Sent D-H key.");
			break;
		case V1_SETUP:
			throw new UnsupportedOperationException();
		}
	}

	public void startV2Auth() throws OtrException {
		logger.info("Starting Authenticated Key Exchange");
		this.reset();
		this.setProtocolVersion(2);
		this.setAuthenticationState(AuthContext.AWAITING_DHKEY);
		logger.info("Sending D-H Commit.");
		try {
			getListener().injectMessage(getSessionID(),
					this.getDHCommitMessage().writeObject());
		} catch (IOException e) {
			throw new OtrException(e);
		}
	}

	private void setSessionID(SessionID sessionID) {
		this.sessionID = sessionID;
	}

	private SessionID getSessionID() {
		return sessionID;
	}

	private PublicKey remoteLongTermPublicKey;

	public PublicKey getRemoteLongTermPublicKey() {
		return remoteLongTermPublicKey;
	}

	private void setRemoteLongTermPublicKey(PublicKey pubKey) {
		this.remoteLongTermPublicKey = pubKey;
	}
}
