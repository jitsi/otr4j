package net.java.otr4j.protocol;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;

import org.apache.log4j.Logger;
import net.java.otr4j.message.*;
import net.java.otr4j.message.encoded.*;
import net.java.otr4j.message.unencoded.*;
import net.java.otr4j.protocol.crypto.CryptoConstants;
import net.java.otr4j.protocol.crypto.CryptoUtils;
import net.java.otr4j.utils.Utils;

public final class StateMachine {

	private static Logger logger = Logger.getLogger(StateMachine.class);

	public static String receivingMessage(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, SignatureException {

		ConnContext ctx = userState.getConnContext(user, account, protocol);
		int policy = listener.getPolicy(ctx);

		if (!PolicyUtils.getAllowV1(policy) && !PolicyUtils.getAllowV2(policy)) {
			return msgText;
		}

		if (!msgText.startsWith(MessageHeader.BASE)) {
			PlainTextMessage plainTextMessage = new PlainTextMessage(msgText);
			return receivingPlainTextMessage(ctx, listener, plainTextMessage);
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
					new RevealSignatureMessage(msgText));
		} else if (msgText.startsWith(MessageHeader.SIGNATURE)) {
			throw new UnsupportedOperationException();
		} else if (msgText.startsWith(MessageHeader.V1_KEY_EXCHANGE)) {
			throw new UnsupportedOperationException();
		} else if (msgText.startsWith(MessageHeader.DATA1)
				|| msgText.startsWith(MessageHeader.DATA1)) {
			throw new UnsupportedOperationException();
		} else if (msgText.startsWith(MessageHeader.ERROR)) {
			receivingErrorMessage(ctx, listener, new ErrorMessage(msgText));
			// User needs to know nothing about Error messages.
		} else {
			logger.debug("Uknown message type.");
		}

		return msgText;
	}

	private static void receivingRevealSignatureMessage(ConnContext ctx,
			OTR4jListener listener, RevealSignatureMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		logger.debug("Received reveal signature message.");
		int policy = listener.getPolicy(ctx);
		if (!PolicyUtils.getAllowV2(policy))
		{
			logger.debug("Policy does not allow OTRv2, ignoring message.");
			return;
		}

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case AWAITING_REVEALSIG:
			byte[] r = msg.revealedKey;
			byte[] encryptedSignature = msg.encryptedSignature;
			byte[] signatureMac = msg.signatureMac;
			byte[] gx = CryptoUtils.aesDescrypt(r, auth.their_yEncrypted);

			byte[] gxHash = CryptoUtils.sha256Hash(gx);
			if (!Arrays.equals(gxHash, auth.their_yHash)) {
				logger.debug("Hashes don't match, ignoring message.");
				return;
			}
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

					authInitialize(auth);

					DHCommitMessage dhCommitMessage = new DHCommitMessage(2,
							auth.r, (DHPublicKey) auth.our_dh.getPublic());
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
			logger.debug("Query message with V2 support found, starting V2 AKE.");
			AuthenticationInfo auth = ctx.authenticationInfo;
			authInitialize(auth);

			DHCommitMessage dhCommitMessage = new DHCommitMessage(2, auth.r,
					(DHPublicKey) auth.our_dh.getPublic());
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
			if (PolicyUtils.getAllowV1(policy)) {
				versions.add(1);
			}
			if (PolicyUtils.getAllowV2(policy)) {
				versions.add(2);
			}
			QueryMessage queryMessage = new QueryMessage(versions);

			logger.debug("Sending Query");
			listener.injectMessage(queryMessage.toString());
		}
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

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case NONE: {
			logger.debug("Storing encrypted gx and encrypted gx hash.");
			auth.their_yEncrypted = msg.gxEncrypted;
			auth.their_yHash = msg.gxHash;

			authInitialize(auth);

			DHKeyMessage dhKey = new DHKeyMessage(2, (DHPublicKey) auth.our_dh
					.getPublic());
			auth.authenticationState = AuthenticationState.AWAITING_REVEALSIG;

			logger.debug("Sending D-H key.");
			listener.injectMessage(dhKey.toString());
			break;
		}
		case AWAITING_DHKEY: {
			BigInteger ourHash = new BigInteger(auth.hashgx);
			BigInteger theirHash = new BigInteger(msg.gxHash);

			if (theirHash.abs().compareTo(ourHash.abs()) == -1) {
				logger
						.debug("Ignore the incoming D-H Commit message, but resend your D-H Commit message.");
				DHCommitMessage dhCommit = new DHCommitMessage(2, auth.r,
						(DHPublicKey) auth.our_dh.getPublic());

				logger.debug("Sending D-H Commit.");
				listener.injectMessage(dhCommit.toString());
			} else {
				logger.debug("Storing encrypted gx and encrypted gx hash.");

				auth.their_yEncrypted = msg.gxEncrypted;
				auth.their_yHash = msg.gxHash;

				authInitialize(auth);

				DHKeyMessage dhKey = new DHKeyMessage(2,
						(DHPublicKey) auth.our_dh.getPublic());
				auth.authenticationState = AuthenticationState.AWAITING_REVEALSIG;

				logger.debug("Sending D-H key.");
				listener.injectMessage(dhKey.toString());
			}
			break;
		}
		case AWAITING_REVEALSIG: {
			logger.debug("Storing encrypted gx and encrypted gx hash.");
			auth.their_yEncrypted = msg.gxEncrypted;
			auth.their_yHash = msg.gxHash;

			DHKeyMessage dhKey = new DHKeyMessage(ctx.our_dh.size() - 1,
					(DHPublicKey) auth.our_dh.getPublic());

			auth.authenticationState = AuthenticationState.AWAITING_REVEALSIG;

			logger.debug("Sending D-H key.");
			listener.injectMessage(dhKey.toString());
			break;
		}
		case AWAITING_SIG:
		case V1_SETUP: {
			throw new UnsupportedOperationException();
		}
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
			// If ALLOW_V2 is not set, ignore this message.
			return;
		}

		Boolean replyRevealSig = false;

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.authenticationState) {
		case AWAITING_DHKEY:
			auth.their_pub = msg.gy;

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
			// TODO load private key from disk
			KeyPair pair = listener.createPrivateKey(account, protocol);
			PrivateKey privKey = pair.getPrivate();
			PublicKey pubKey = pair.getPublic();

			KeyPair our_pair = auth.our_dh;
			DHPublicKey gxKey = (DHPublicKey) our_pair.getPublic();
			DHPublicKey gyKey = auth.their_pub;
			int keyidB = auth.our_keyid;
			BigInteger s = CryptoUtils.generateSecret(our_pair);
			byte[] r = auth.r;
			RevealSignatureMessage revealSignatureMessage = new RevealSignatureMessage(
					protocolVersion, s, gxKey, gyKey, keyidB, privKey, pubKey,
					r);

			auth.authenticationState = AuthenticationState.AWAITING_SIG;
			logger.debug("Sending Reveal Signature.");
			listener.injectMessage(revealSignatureMessage.toString());
		}

	}

	private static void authInitialize(AuthenticationInfo auth)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException {

		logger.debug("Picking random key r.");
		byte[] r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);
		auth.r = r;
		logger.debug("Generating own D-H key pair.");
		auth.our_dh = CryptoUtils.generateDHKeyPair();
		auth.our_keyid = 1;
	}
}
