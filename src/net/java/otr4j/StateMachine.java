package net.java.otr4j;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Vector;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import org.apache.log4j.Logger;

import net.java.otr4j.context.ConnContext;
import net.java.otr4j.context.auth.AuthenticationInfo;
import net.java.otr4j.context.auth.AuthenticationInfoUtils;
import net.java.otr4j.context.auth.AuthenticationState;
import net.java.otr4j.crypto.CryptoConstants;
import net.java.otr4j.crypto.CryptoUtils;
import net.java.otr4j.message.*;
import net.java.otr4j.message.encoded.*;
import net.java.otr4j.message.encoded.signature.RevealSignatureMessage;
import net.java.otr4j.message.encoded.signature.SignatureMessage;
import net.java.otr4j.message.unencoded.*;
import net.java.otr4j.message.unencoded.query.PlainTextMessage;
import net.java.otr4j.message.unencoded.query.QueryMessage;

public final class StateMachine {

	private static Logger logger = Logger.getLogger(StateMachine.class);

	public static String receivingMessage(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, SignatureException, IOException {

		if (Utils.IsNullOrEmpty(msgText))
			return msgText;

		logger
				.debug("-- " + account + " received a message from " + user
						+ ".");
		ConnContext ctx = userState.getConnContext(user, account, protocol);
		int policy = listener.getPolicy(ctx);

		if (!PolicyUtils.getAllowV1(policy) && !PolicyUtils.getAllowV2(policy)) {
			logger
					.debug("Policy does not allow neither V1 not V2, ignoring message.");
			return msgText;
		}

		int msgType = 0;
		if (!msgText.startsWith(MessageHeader.BASE)) {
			msgType = MessageType.PLAINTEXT;
		} else if (msgText.startsWith(MessageHeader.DH_COMMIT)) {
			msgType = MessageType.DH_COMMIT;
		} else if (msgText.startsWith(MessageHeader.DH_KEY)) {
			msgType = MessageType.DH_KEY;
		} else if (msgText.startsWith(MessageHeader.REVEALSIG)) {
			msgType = MessageType.REVEALSIG;
		} else if (msgText.startsWith(MessageHeader.SIGNATURE)) {
			msgType = MessageType.SIGNATURE;
		} else if (msgText.startsWith(MessageHeader.V1_KEY_EXCHANGE)) {
			msgType = MessageType.V1_KEY_EXCHANGE;
		} else if (msgText.startsWith(MessageHeader.DATA1)
				|| msgText.startsWith(MessageHeader.DATA1)) {
			msgType = MessageType.DATA;
		} else if (msgText.startsWith(MessageHeader.ERROR)) {
			msgType = MessageType.ERROR;
		} else if (msgText.startsWith(MessageHeader.QUERY1)
				|| msgText.startsWith(MessageHeader.QUERY2)) {
			msgType = MessageType.QUERY;
		} else {
			msgType = MessageType.UKNOWN;
		}

		switch (msgType) {
		case MessageType.DATA:
			throw new UnsupportedOperationException();
		case MessageType.DH_COMMIT:
			DHCommitMessage dhCommit = new DHCommitMessage();
			dhCommit.readObject(new ByteArrayInputStream(EncodedMessageUtils
					.decodeMessage(msgText)));
			receivingDHCommitMessage(ctx, listener, dhCommit);
			break;
		case MessageType.DH_KEY:
			DHKeyMessage dhKey = new DHKeyMessage();
			dhKey.readObject(new ByteArrayInputStream(EncodedMessageUtils
					.decodeMessage(msgText)));
			receivingDHKeyMessage(ctx, listener, dhKey, account, protocol);
			break;
		case MessageType.REVEALSIG:
			RevealSignatureMessage revealSigMessage = new RevealSignatureMessage();
			revealSigMessage.readObject(new ByteArrayInputStream(
					EncodedMessageUtils.decodeMessage(msgText)));
			receivingRevealSignatureMessage(ctx, listener, revealSigMessage,
					account, protocol);
			break;
		case MessageType.SIGNATURE:
			SignatureMessage sigMessage = new SignatureMessage();
			sigMessage.readObject(new ByteArrayInputStream(EncodedMessageUtils
					.decodeMessage(msgText)));
			receivingSignatureMessage(ctx, listener, sigMessage);
			break;
		case MessageType.ERROR:
			receivingErrorMessage(ctx, listener, new ErrorMessage(msgText));
			// User needs to know nothing about Error messages.
			break;
		case MessageType.PLAINTEXT:
			return receivingPlainTextMessage(ctx, listener,
					new PlainTextMessage(msgText));
		case MessageType.QUERY:
			receivingQueryMessage(ctx, listener, new QueryMessage(msgText));
			// User needs to know nothing about Query messages.
			break;
		case MessageType.V1_KEY_EXCHANGE:
			throw new UnsupportedOperationException();
		default:
			break;
		}

		return msgText;
	}

	private static void receivingSignatureMessage(ConnContext ctx,
			OTR4jListener listener, SignatureMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException, IOException, SignatureException {
		logger.debug("Received signature message.");

		int policy = listener.getPolicy(ctx);
		if (!PolicyUtils.getAllowV2(policy)) {
			logger.debug("Policy does not allow OTRv2, ignoring message.");
			return;
		}

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case AWAITING_SIG:
			byte[] remoteXEncrypted = msg.xEncrypted;
			byte[] remoteXEncryptedMAC = CryptoUtils.sha256Hmac160(
					remoteXEncrypted, auth.m2p);
			if (!Arrays.equals(remoteXEncryptedMAC, msg.xEncryptedMAC)) {
				logger.debug("Signature MACs are not equal, ignoring message.");
				return;
			}

			byte[] remoteXDecrypted = CryptoUtils.aesDecrypt(auth.cp, msg.xEncrypted);

			MysteriousX remoteX = new MysteriousX();
			remoteX.readObject(new ByteArrayInputStream(remoteXDecrypted));

			MysteriousM remoteM = new MysteriousM(auth.m1p,
					auth.remoteDHPublicKey, (DHPublicKey) auth.localDHKeyPair
							.getPublic(), remoteX.longTermPublicKey,
					remoteX.dhKeyID);

			if (!CryptoUtils.verify(remoteM.compute(),
					remoteX.longTermPublicKey, remoteX.signature)) {
				logger.debug("Signature verification failed.");
				return;
			}
			break;
		default:
			break;
		}

	}

	private static void receivingRevealSignatureMessage(ConnContext ctx,
			OTR4jListener listener, RevealSignatureMessage msg, String account,
			String protocol) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, SignatureException, InvalidKeySpecException,
			IOException {

		logger.debug("Received reveal signature message.");
		int policy = listener.getPolicy(ctx);
		if (!PolicyUtils.getAllowV2(policy)) {
			logger.debug("Policy does not allow OTRv2, ignoring message.");
			return;
		}

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case AWAITING_REVEALSIG:
			byte[] r = msg.revealedKey;
			byte[] remoteDHPublicKeyDecrypted = CryptoUtils.aesDecrypt(r,
					auth.remoteDHPublicKeyEncrypted);

			byte[] remoteDHPublicKeyHash = CryptoUtils
					.sha256Hash(remoteDHPublicKeyDecrypted);
			if (!Arrays.equals(remoteDHPublicKeyHash,
					auth.remoteDHPublicKeyHash)) {
				logger.debug("Hashes don't match, ignoring message.");
				return;
			}

			// Verifies that Bob's gx is a legal value (2 <= gx <= modulus-2)
			BigInteger remoteDHPublicKeyMpi = new BigInteger(remoteDHPublicKeyDecrypted);
			if (remoteDHPublicKeyMpi
					.compareTo(CryptoConstants.MODULUS_MINUS_TWO) > 0) {
				logger.debug("gx <= modulus-2, ignoring message.");
				return;
			} else if (remoteDHPublicKeyMpi
					.compareTo(CryptoConstants.BIGINTEGER_TWO) < 0) {
				logger.debug("2 <= gx, ignoring message.");
				return;
			}

			auth.remoteDHPublicKey = CryptoUtils
					.getDHPublicKey(remoteDHPublicKeyMpi);
			logger.debug("Calculating secret key.");
			auth.s = CryptoUtils.generateSecret(auth.localDHKeyPair
					.getPrivate(), auth.remoteDHPublicKey);

			auth.c = AuthenticationInfoUtils.getC(auth.s);
			auth.cp = AuthenticationInfoUtils.getCp(auth.s);
			auth.m1 = AuthenticationInfoUtils.getM1(auth.s);
			auth.m1p = AuthenticationInfoUtils.getM1p(auth.s);
			auth.m2 = AuthenticationInfoUtils.getM2(auth.s);
			auth.m2p = AuthenticationInfoUtils.getM2p(auth.s);

			byte[] remoteXEncrypted = msg.xEncrypted;
			byte[] remoteXEncryptedMAC = CryptoUtils.sha256Hmac160(
					remoteXEncrypted, auth.m2);
			if (!Arrays.equals(remoteXEncryptedMAC, msg.xEncryptedMAC)) {
				logger.debug("Signature MACs are not equal, ignoring message.");
				return;
			}

			byte[] remoteXDecrypted = CryptoUtils.aesDecrypt(auth.c, msg.xEncrypted);

			MysteriousX remoteX = new MysteriousX();
			remoteX.readObject(new ByteArrayInputStream(remoteXDecrypted));

			MysteriousM remoteM = new MysteriousM(auth.m1,
					auth.remoteDHPublicKey, (DHPublicKey) auth.localDHKeyPair
							.getPublic(), remoteX.longTermPublicKey,
					remoteX.dhKeyID);

			if (!CryptoUtils.verify(remoteM.compute(),
					remoteX.longTermPublicKey, remoteX.signature)) {
				logger.debug("Signature verification failed.");
				return;
			}

			auth.localLongTermKeyPair = listener.getKeyPair(account, protocol);
			logger.debug("Calculating our M and our X.");
			DHPublicKey localDHPublicKey = (DHPublicKey) auth.localDHKeyPair
					.getPublic();
			MysteriousM localM = new MysteriousM(auth.m1p, localDHPublicKey,
					auth.remoteDHPublicKey, auth.localLongTermKeyPair
							.getPublic(), auth.localDHPrivateKeyID);

			byte[] localSignature = CryptoUtils.sign(localM.compute(),
					auth.localLongTermKeyPair.getPrivate());
			MysteriousX localX = new MysteriousX(auth.localLongTermKeyPair
					.getPublic(), auth.localDHPrivateKeyID, localSignature);

			ByteArrayOutputStream localXbos = new ByteArrayOutputStream();
			localX.writeObject(localXbos);
			byte[] localXbytes = localXbos.toByteArray();

			auth.localXEncrypted = CryptoUtils.aesEncrypt(auth.cp, localXbytes);
			auth.localXEncryptedMac = CryptoUtils.sha256Hmac160(
					auth.localXEncrypted, auth.m2p);

			SignatureMessage msgSig = new SignatureMessage(2,
					auth.localXEncryptedMac, auth.localXEncrypted);
			injectMessage(listener, msgSig);
			break;
		default:
			break;
		}
	}

	private static String receivingPlainTextMessage(ConnContext ctx,
			OTR4jListener listener, PlainTextMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, IOException {
		Vector<Integer> versions = msg.versions;
		int policy = listener.getPolicy(ctx);
		if (versions.size() < 1) {
			logger
					.debug("Received plaintext message without the whitespace tag.");
			switch (ctx.messageState) {
			case ENCRYPTED:
			case FINISHED:
				// Display the message to the user, but warn him that the
				// message was received unencrypted.
				listener.showWarning("The message was received unencrypted.");
				return msg.cleanText;
			case PLAINTEXT:
				// Simply display the message to the user. If REQUIRE_ENCRYPTION
				// is set, warn him that the message was received unencrypted.
				if (PolicyUtils.getRequireEncryption(policy)) {
					listener
							.showWarning("The message was received unencrypted.");
				}
				break;
			}
		} else {
			logger.debug("Received plaintext message with the whitespace tag.");
			String cleanText = msg.cleanText;
			switch (ctx.messageState) {
			case ENCRYPTED:
			case FINISHED:
				// Remove the whitespace tag and display the message to the
				// user, but warn him that the message was received unencrypted.
				listener.showWarning("The message was received unencrypted.");
				return cleanText;
			case PLAINTEXT:
				// Remove the whitespace tag and display the message to the
				// user. If REQUIRE_ENCRYPTION is set, warn him that the message
				// was received unencrypted.
				if (PolicyUtils.getRequireEncryption(policy)) {
					listener
							.showWarning("The message was received unencrypted.");
				}
				return cleanText;
			}

			if (PolicyUtils.getWhiteSpaceStartsAKE(policy)) {
				logger.debug("WHITESPACE_START_AKE is set");

				if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
					logger.debug("V2 tag found, starting v2 AKE.");
					AuthenticationInfo auth = ctx.authenticationInfo;
					auth.initialize();

					DHCommitMessage dhCommitMessage = new DHCommitMessage(2,
							auth.localDHPublicKeyHash,
							auth.localDHPublicKeyEncrypted);
					auth.authenticationState = AuthenticationState.AWAITING_DHKEY;

					logger.debug("Sending D-H Commit.");
					injectMessage(listener, dhCommitMessage);
				} else if (versions.contains(1)
						&& PolicyUtils.getAllowV1(policy)) {
					throw new UnsupportedOperationException();
				}
			}
		}

		return null;
	}

	private static void injectMessage(OTR4jListener listener,
			EncodedMessageBase msg) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		msg.writeObject(bos);
		String encodedMessage = EncodedMessageUtils.encodeMessage(bos
				.toByteArray());
		listener.injectMessage(encodedMessage);
	}

	private static void receivingQueryMessage(ConnContext ctx,
			OTR4jListener listener, QueryMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, IOException {
		logger.debug("Received query message.");
		Vector<Integer> versions = msg.versions;
		int policy = listener.getPolicy(ctx);
		if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
			logger
					.debug("Query message with V2 support found, starting V2 AKE.");
			AuthenticationInfo auth = ctx.authenticationInfo;
			auth.initialize();

			DHCommitMessage dhCommitMessage = new DHCommitMessage(2,
					auth.localDHPublicKeyHash, auth.localDHPublicKeyEncrypted);
			auth.authenticationState = AuthenticationState.AWAITING_DHKEY;

			logger.debug("Sending D-H Commit.");
			injectMessage(listener, dhCommitMessage);
		} else if (versions.contains(1) && PolicyUtils.getAllowV1(policy)) {
			throw new UnsupportedOperationException();
		}
	}

	private static void receivingErrorMessage(ConnContext ctx,
			OTR4jListener listener, ErrorMessage msg) {
		logger.debug("Received error message.");
		listener.showError(msg.error);
		int policy = listener.getPolicy(ctx);
		if (PolicyUtils.getErrorStartsAKE(policy)) {
			logger.debug("Error message starts AKE.");
			Vector<Integer> versions = new Vector<Integer>();
			if (PolicyUtils.getAllowV1(policy))
				versions.add(1);

			if (PolicyUtils.getAllowV2(policy))
				versions.add(2);

			QueryMessage queryMessage = new QueryMessage(versions);

			logger.debug("Sending Query");
			listener.injectMessage(queryMessage.toString());
		}
	}

	private enum ReceivingDHCommitMessageActions {
		RETRANSMIT_OLD_DH_KEY, SEND_NEW_DH_KEY, RETRANSMIT_DH_COMMIT,
	}

	private static void receivingDHCommitMessage(ConnContext ctx,
			OTR4jListener listener, DHCommitMessage msg)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, IOException {

		logger.debug("Received D-H Commit.");

		if (!PolicyUtils.getAllowV2(listener.getPolicy(ctx))) {
			logger.debug("ALLOW_V2 is not set, ignore this message.");
			return;
		}

		// Set SEND_DH_KEY as default action.
		ReceivingDHCommitMessageActions action = ReceivingDHCommitMessageActions.SEND_NEW_DH_KEY;

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case NONE:
			action = ReceivingDHCommitMessageActions.SEND_NEW_DH_KEY;
			break;

		case AWAITING_DHKEY:
			BigInteger ourHash = new BigInteger(auth.localDHPublicKeyHash)
					.abs();
			BigInteger theirHash = new BigInteger(msg.dhPublicKeyHash).abs();

			if (theirHash.compareTo(ourHash) == -1) {
				action = ReceivingDHCommitMessageActions.RETRANSMIT_DH_COMMIT;
			} else {
				action = ReceivingDHCommitMessageActions.SEND_NEW_DH_KEY;
			}
			break;

		case AWAITING_REVEALSIG:
			action = ReceivingDHCommitMessageActions.RETRANSMIT_OLD_DH_KEY;
			break;
		case AWAITING_SIG:
			action = ReceivingDHCommitMessageActions.SEND_NEW_DH_KEY;
			break;
		case V1_SETUP:
			throw new UnsupportedOperationException();
		}

		switch (action) {
		case RETRANSMIT_DH_COMMIT:
			logger
					.debug("Ignore the incoming D-H Commit message, but resend your D-H Commit message.");
			DHCommitMessage dhCommit = new DHCommitMessage(2,
					auth.localDHPublicKeyHash, auth.localDHPublicKeyEncrypted);

			logger.debug("Sending D-H Commit.");
			injectMessage(listener, dhCommit);
			break;
		case SEND_NEW_DH_KEY:
			auth.initialize();
		case RETRANSMIT_OLD_DH_KEY:
			logger.debug("Storing encrypted gx and encrypted gx hash.");
			auth.remoteDHPublicKeyEncrypted = msg.dhPublicKeyEncrypted;
			auth.remoteDHPublicKeyHash = msg.dhPublicKeyHash;

			DHKeyMessage dhKey = new DHKeyMessage(2,
					(DHPublicKey) auth.localDHKeyPair.getPublic());
			auth.authenticationState = AuthenticationState.AWAITING_REVEALSIG;

			logger.debug("Sending D-H key.");
			injectMessage(listener, dhKey);
		default:
			break;
		}
	}

	private static void receivingDHKeyMessage(ConnContext ctx,
			OTR4jListener listener, DHKeyMessage msg, String account,
			String protocol) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		logger.debug("Received D-H Key.");
		if (!PolicyUtils.getAllowV2(listener.getPolicy(ctx))) {
			logger.debug("If ALLOW_V2 is not set, ignore this message.");
			return;
		}

		Boolean replyRevealSig = false;

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case AWAITING_DHKEY:
			logger.debug("Verify received D-H Public Key is a legal value.");
			if (msg.dhPublicKey.getY().compareTo(
					CryptoConstants.MODULUS_MINUS_TWO) > 0) {
				logger.debug("Illegal D-H Public Key value, Ignoring message.");
				return;
			} else if (msg.dhPublicKey.getY().compareTo(
					CryptoConstants.BIGINTEGER_TWO) < 0) {
				logger.debug("Illegal D-H Public Key value, Ignoring message.");
				return;
			}

			logger.debug("Computing secret.");
			auth.remoteDHPublicKey = msg.dhPublicKey;
			auth.s = CryptoUtils.generateSecret(auth.localDHKeyPair
					.getPrivate(), auth.remoteDHPublicKey);

			logger.debug("Compute various keys by hashing secret.");
			auth.c = AuthenticationInfoUtils.getC(auth.s);
			auth.cp = AuthenticationInfoUtils.getCp(auth.s);
			auth.m1 = AuthenticationInfoUtils.getM1(auth.s);
			auth.m1p = AuthenticationInfoUtils.getM1p(auth.s);
			auth.m2 = AuthenticationInfoUtils.getM2(auth.s);
			auth.m2p = AuthenticationInfoUtils.getM2p(auth.s);

			logger.debug("Computing M");
			KeyPair keyPair = listener.getKeyPair(account, protocol);
			auth.localLongTermKeyPair = keyPair;

			DHPublicKey ourDHPublicKey = (DHPublicKey) auth.localDHKeyPair
					.getPublic();
			MysteriousM m = new MysteriousM(auth.m1, ourDHPublicKey,
					auth.remoteDHPublicKey, auth.localLongTermKeyPair
							.getPublic(), auth.localDHPrivateKeyID);

			byte[] mbytes = m.compute();
			byte[] signature = CryptoUtils.sign(mbytes,
					auth.localLongTermKeyPair.getPrivate());

			logger.debug("Computing X");
			MysteriousX x = new MysteriousX(auth.localLongTermKeyPair
					.getPublic(), auth.localDHPrivateKeyID, signature);

			ByteArrayOutputStream xstream = new ByteArrayOutputStream();
			x.writeObject(xstream);
			byte[] xbytes = xstream.toByteArray();

			logger.debug("Encryting X");
			auth.localXEncrypted = CryptoUtils.aesEncrypt(auth.c, xbytes);
			logger.debug("Hashing encrypted X");
			auth.localXEncryptedMac = CryptoUtils.sha256Hmac160(
					auth.localXEncrypted, auth.m2);

			replyRevealSig = true;
			break;
		case AWAITING_SIG:
			if (msg.dhPublicKey.getEncoded().equals(ctx.their_y.getFirst())) {
				replyRevealSig = true;
			}
			break;
		default:
			break;
		}

		if (replyRevealSig) {
			int protocolVersion = 2;

			RevealSignatureMessage revealSignatureMessage = new RevealSignatureMessage(
					protocolVersion, auth.r, auth.localXEncryptedMac,
					auth.localXEncrypted);

			auth.authenticationState = AuthenticationState.AWAITING_SIG;
			logger.debug("Sending Reveal Signature.");
			injectMessage(listener, revealSignatureMessage);
		}

	}
}
