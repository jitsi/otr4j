package net.java.otr4j;

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
			NoSuchProviderException, SignatureException {

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

		if (!msgText.startsWith(MessageHeader.BASE)) {
			return receivingPlainTextMessage(ctx, listener,
					new PlainTextMessage(msgText));
		} else if (msgText.startsWith(MessageHeader.QUERY1)
				|| msgText.startsWith(MessageHeader.QUERY2)) {
			receivingQueryMessage(ctx, listener, new QueryMessage(msgText));
			// User needs to know nothing about Query messages.
		} else if (msgText.startsWith(MessageHeader.DH_COMMIT)) {
			receivingDHCommitMessage(ctx, listener,
					new DHCommitMessage(msgText));
		} else if (msgText.startsWith(MessageHeader.DH_KEY)) {
			receivingDHKeyMessage(ctx, listener, new DHKeyMessage(msgText),
					account, protocol);
		} else if (msgText.startsWith(MessageHeader.REVEALSIG)) {
			receivingRevealSignatureMessage(ctx, listener,
					new RevealSignatureMessage(msgText), account, protocol);
		} else if (msgText.startsWith(MessageHeader.SIGNATURE)) {
			receivingSignatureMessage(ctx, listener, new SignatureMessage(
					msgText));
		} else if (msgText.startsWith(MessageHeader.V1_KEY_EXCHANGE)) {
			throw new UnsupportedOperationException();
		} else if (msgText.startsWith(MessageHeader.DATA1)
				|| msgText.startsWith(MessageHeader.DATA1)) {
			throw new UnsupportedOperationException();
		} else if (msgText.startsWith(MessageHeader.ERROR)) {
			receivingErrorMessage(ctx, listener, new ErrorMessage(msgText));
			// User needs to know nothing about Error messages.
		} else {
			logger.debug("Oups.. Uknown message type :S");
		}

		return msgText;
	}

	private static void receivingSignatureMessage(ConnContext ctx,
			OTR4jListener listener, SignatureMessage signatureMessage) {
		logger.debug("Received signature message. Not Implemented Yet.");
	}

	private static void receivingRevealSignatureMessage(ConnContext ctx,
			OTR4jListener listener, RevealSignatureMessage msg, String account,
			String protocol) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, SignatureException, InvalidKeySpecException {

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
			byte[] gx = CryptoUtils.aesDecrypt(r,
					auth.theirDHPublicKeyEncrypted);

			byte[] gxHash = CryptoUtils.sha256Hash(gx);
			if (!Arrays.equals(gxHash, auth.theirDHPublicKeyHash)) {
				logger.debug("Hashes don't match, ignoring message.");
				return;
			}

			// Verifies that Bob's gx is a legal value (2 <= gx <= modulus-2)
			BigInteger gxmpi = new BigInteger(gx);
			if (gxmpi.compareTo(CryptoConstants.MODULUS_MINUS_TWO) > 0) {
				logger.debug("gx <= modulus-2, ignoring message.");
				return;
			} else if (gxmpi.compareTo(CryptoConstants.BIGINTEGER_TWO) < 0) {
				logger.debug("2 <= gx, ignoring message.");
				return;
			}

			int protocolVersion = 2;

			auth.theirDHPublicKey = CryptoUtils.getDHPublicKey(gxmpi);
			logger.debug("Calculating secret key.");
			auth.s = CryptoUtils.generateSecret(auth.ourDHKeyPair.getPrivate(),
					auth.theirDHPublicKey);

			// TODO load private key from disk or request it from host
			// application
			KeyPair keyPair = listener.getKeyPair(account, protocol);
			auth.ourLongTermKeyPair = keyPair;

			auth.c = AuthenticationInfoUtils.getC(auth.s);
			auth.cp = AuthenticationInfoUtils.getCp(auth.s);
			auth.m1 = AuthenticationInfoUtils.getM1(auth.s);
			auth.m1p = AuthenticationInfoUtils.getM1p(auth.s);
			auth.m2 = AuthenticationInfoUtils.getM2(auth.s);
			auth.m2p = AuthenticationInfoUtils.getM2p(auth.s);

			byte[] encryptedSignature = msg.encryptedSignature;
			byte[] calculatedMAC = CryptoUtils.sha256Hmac160(
					encryptedSignature, auth.m2);
			if (!Arrays.equals(calculatedMAC, msg.signatureMac)) {
				logger.debug("Signature MACs are not equal, ignoring message.");
				return;
			}

			/*
			 * SignatureMessage msgSig = new SignatureMessage(protocolVersion,
			 * auth.ourXMac, auth.ourXEncrypted);
			 * listener.injectMessage(msgSig.toString());
			 */
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
			NoSuchProviderException {
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
							auth.ourDHPublicKeyHash,
							auth.ourDHPublicKeyEncrypted);
					auth.authenticationState = AuthenticationState.AWAITING_DHKEY;

					logger.debug("Sending D-H Commit.");
					listener.injectMessage(dhCommitMessage.toString());
				} else if (versions.contains(1)
						&& PolicyUtils.getAllowV1(policy)) {
					throw new UnsupportedOperationException();
				}
			}
		}

		return null;
	}

	private static void receivingQueryMessage(ConnContext ctx,
			OTR4jListener listener, QueryMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException {
		logger.debug("Received query message.");
		Vector<Integer> versions = msg.versions;
		int policy = listener.getPolicy(ctx);
		if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
			logger
					.debug("Query message with V2 support found, starting V2 AKE.");
			AuthenticationInfo auth = ctx.authenticationInfo;
			auth.initialize();

			DHCommitMessage dhCommitMessage = new DHCommitMessage(2,
					auth.ourDHPublicKeyHash, auth.ourDHPublicKeyEncrypted);
			auth.authenticationState = AuthenticationState.AWAITING_DHKEY;

			logger.debug("Sending D-H Commit.");
			listener.injectMessage(dhCommitMessage.toString());
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
			IllegalBlockSizeException, BadPaddingException {

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
			BigInteger ourHash = new BigInteger(auth.ourDHPublicKeyHash);
			BigInteger theirHash = new BigInteger(msg.gxHash);

			if (theirHash.abs().compareTo(ourHash.abs()) == -1) {
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

		if (action == ReceivingDHCommitMessageActions.SEND_NEW_DH_KEY)
			auth.initialize();

		switch (action) {
		case RETRANSMIT_DH_COMMIT:
			logger
					.debug("Ignore the incoming D-H Commit message, but resend your D-H Commit message.");
			DHCommitMessage dhCommit = new DHCommitMessage(2,
					auth.ourDHPublicKeyHash, auth.ourDHPublicKeyEncrypted);

			logger.debug("Sending D-H Commit.");
			listener.injectMessage(dhCommit.toString());
			break;
		case RETRANSMIT_OLD_DH_KEY:
		case SEND_NEW_DH_KEY:
			logger.debug("Storing encrypted gx and encrypted gx hash.");
			auth.theirDHPublicKeyEncrypted = msg.gxEncrypted;
			auth.theirDHPublicKeyHash = msg.gxHash;

			DHKeyMessage dhKey = new DHKeyMessage(2,
					(DHPublicKey) auth.ourDHKeyPair.getPublic());
			auth.authenticationState = AuthenticationState.AWAITING_REVEALSIG;

			logger.debug("Sending D-H key.");
			listener.injectMessage(dhKey.toString());
		default:
			break;
		}
	}

	private static void receivingDHKeyMessage(ConnContext ctx,
			OTR4jListener listener, DHKeyMessage msg, String account,
			String protocol) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		logger.debug("Received D-H Key.");
		if (!PolicyUtils.getAllowV2(listener.getPolicy(ctx))) {
			logger.debug("If ALLOW_V2 is not set, ignore this message.");
			return;
		}

		Boolean replyRevealSig = false;

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case AWAITING_DHKEY:
			// Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)
			if (msg.gy.getY().compareTo(CryptoConstants.MODULUS_MINUS_TWO) > 0) {
				return;
			} else if (msg.gy.getY().compareTo(CryptoConstants.BIGINTEGER_TWO) < 0) {
				return;
			}

			auth.theirDHPublicKey = msg.gy;
			logger.debug("Calculating secret key.");
			auth.s = CryptoUtils.generateSecret(auth.ourDHKeyPair.getPrivate(),
					auth.theirDHPublicKey);

			auth.c = AuthenticationInfoUtils.getC(auth.s);
			auth.cp = AuthenticationInfoUtils.getCp(auth.s);
			auth.m1 = AuthenticationInfoUtils.getM1(auth.s);
			auth.m1p = AuthenticationInfoUtils.getM1p(auth.s);
			auth.m2 = AuthenticationInfoUtils.getM2(auth.s);
			auth.m2p = AuthenticationInfoUtils.getM2p(auth.s);

			// TODO load private key from disk or request it from host
			// application
			KeyPair keyPair = listener.getKeyPair(account, protocol);
			auth.ourLongTermKeyPair = keyPair;

			logger.debug("Calculating our M and our X.");
			DHPublicKey ourDHPublicKey = (DHPublicKey) auth.ourDHKeyPair
					.getPublic();
			MysteriousM m = new MysteriousM(auth.m1, ourDHPublicKey,
					auth.theirDHPublicKey, auth.ourLongTermKeyPair.getPublic(),
					auth.ourDHPrivateKeyID);

			/*BigInteger[] signature = MysteriousXUtils.sign(m.toByteArray(),
					auth.ourLongTermKeyPair.getPrivate());
			MysteriousX x = new MysteriousX(auth.ourDHKeyPair.getPublic(),
					auth.ourDHPrivateKeyID, signature);

			auth.ourXEncrypted = CryptoUtils.aesEncrypt(auth.c, x
					.toByteArray());
			auth.ourXEncryptedMac = CryptoUtils.sha256Hmac160(
					auth.ourXEncrypted, auth.m2);*/

			replyRevealSig = true;
			break;
		case AWAITING_SIG:
			if (msg.gy.getEncoded().equals(ctx.their_y.getFirst())) {
				replyRevealSig = true;
			}
			break;
		default:
			break;
		}

		if (replyRevealSig) {
			int protocolVersion = 2;

			RevealSignatureMessage revealSignatureMessage = new RevealSignatureMessage(
					protocolVersion, auth.r, auth.ourXEncryptedMac,
					auth.ourXEncrypted);

			auth.authenticationState = AuthenticationState.AWAITING_SIG;
			logger.debug("Sending Reveal Signature.");
			listener.injectMessage(revealSignatureMessage.toString());
		}

	}
}
