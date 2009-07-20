/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j;

import java.io.*;
import java.math.*;
import java.security.*;
import java.util.*;
import java.util.logging.*;
import javax.crypto.interfaces.*;

import net.java.otr4j.context.*;
import net.java.otr4j.context.auth.*;
import net.java.otr4j.crypto.*;
import net.java.otr4j.message.*;
import net.java.otr4j.message.encoded.*;
import net.java.otr4j.message.encoded.signature.*;
import net.java.otr4j.message.unencoded.*;
import net.java.otr4j.message.unencoded.query.*;

/**
 * 
 * @author George Politis
 * 
 */
public final class StateMachine {
	private static Logger logger = Logger.getLogger(StateMachine.class
			.getName());

	public static String sendingMessage(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) {
		try {
			ConnContext ctx = userState.getConnContext(user, account, protocol);

			switch (ctx.getMessageState()) {
			case PLAINTEXT:
				return msgText;
			case ENCRYPTED:
				logger.info(account + " sends an encrypted message to " + user
						+ " throught " + protocol + ".");

				// Get encryption keys.
				SessionKeys encryptionKeys = ctx.getEncryptionSessionKeys();
				int senderKeyID = encryptionKeys.localKeyID;
				int receipientKeyID = encryptionKeys.remoteKeyID;

				// Increment CTR.
				encryptionKeys.incrementSendingCtr();
				byte[] ctr = encryptionKeys.getSendingCtr();

				// Encrypt message.
				logger
						.info("Encrypting message with keyids (localKeyID, remoteKeyID) = ("
								+ senderKeyID + ", " + receipientKeyID + ")");
				byte[] encryptedMsg = CryptoUtils.aesEncrypt(encryptionKeys
						.getSendingAESKey(), ctr, msgText.getBytes());

				// Get most recent keys to get the next D-H public key.
				SessionKeys mostRecentKeys = ctx.getMostRecentSessionKeys();
				DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.localPair
						.getPublic();

				// Calculate T.
				MysteriousT t = new MysteriousT(senderKeyID, receipientKeyID,
						nextDH, ctr, encryptedMsg, 2, 0);

				// Calculate T hash.
				byte[] sendingMACKey = encryptionKeys.getSendingMACKey();
				byte[] mac = t.hash(sendingMACKey);

				// Get old MAC keys to be revealed.
				byte[] oldMacKeys = ctx.getOldMacKeys();
				DataMessage msg = new DataMessage(t, mac, oldMacKeys);
				return msg.toUnsafeString();
			case FINISHED:
				return msgText;
			default:
				return msgText;
			}
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Message sending failed.", e);
			return msgText;
		}
	}

	public static String receivingMessage(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) {
		ByteArrayInputStream in = null;
		try {
			if (Utils.IsNullOrEmpty(msgText))
				return msgText;

			ConnContext ctx = userState.getConnContext(user, account, protocol);
			int policy = listener.getPolicy(ctx);

			Boolean allowV1 = PolicyUtils.getAllowV1(policy);
			Boolean allowV2 = PolicyUtils.getAllowV2(policy);
			if (!allowV1 && !allowV2) {
				logger
						.info("Policy does not allow neither V1 not V2, ignoring message.");
				return msgText;
			}

			AuthenticationInfo auth = ctx.getAuthenticationInfo();
			switch (MessageHeader.getMessageType(msgText)) {
			case MessageType.DATA:
				logger.info(account + " received a data message from " + user
						+ ".");
				DataMessage data = new DataMessage();
				in = new ByteArrayInputStream(EncodedMessageUtils
						.decodeMessage(msgText));
				data.readObject(in);
				return receivingDataMessage(ctx, listener, data);
			case MessageType.DH_COMMIT:
				logger.info(account + " received a D-H commit message from "
						+ user + " throught " + protocol + ".");

				if (!allowV2) {
					logger.info("ALLOW_V2 is not set, ignore this message.");
					return null;
				}

				DHCommitMessage dhCommit = new DHCommitMessage();
				in = new ByteArrayInputStream(EncodedMessageUtils
						.decodeMessage(msgText));
				dhCommit.readObject(in);

				switch (auth.getAuthenticationState()) {
				case NONE:
					auth.reset();
					auth.setAuthAwaitingRevealSig(dhCommit);
					logger.info("Sending D-H key.");
					listener.injectMessage(auth.getDHKeyMessage()
							.toUnsafeString());
					break;

				case AWAITING_DHKEY:
					BigInteger ourHash = new BigInteger(1, auth
							.getLocalDHPublicKeyHash());
					BigInteger theirHash = new BigInteger(1, dhCommit
							.getDhPublicKeyHash());

					if (theirHash.compareTo(ourHash) == -1) {
						logger
								.info("Ignore the incoming D-H Commit message, but resend your D-H Commit message.");

						logger.info("Sending D-H Commit.");
						listener.injectMessage(auth.getDHCommitMessage()
								.toUnsafeString());
					} else {
						auth.reset();
						auth.setAuthAwaitingRevealSig(dhCommit);
						logger.info("Sending D-H key.");
						listener.injectMessage(auth.getDHKeyMessage()
								.toUnsafeString());
					}
					break;

				case AWAITING_REVEALSIG:
					auth.setAuthAwaitingRevealSig(dhCommit);
					logger.info("Sending D-H key.");
					listener.injectMessage(auth.getDHKeyMessage()
							.toUnsafeString());
					break;
				case AWAITING_SIG:
					auth.reset();
					auth.setAuthAwaitingRevealSig(dhCommit);
					logger.info("Sending D-H key.");
					listener.injectMessage(auth.getDHKeyMessage()
							.toUnsafeString());
					break;
				case V1_SETUP:
					throw new UnsupportedOperationException();
				}
				return null;
			case MessageType.DH_KEY:
				logger.info(account + " received a D-H key message from "
						+ user + " throught " + protocol + ".");

				if (!allowV2) {
					logger.info("If ALLOW_V2 is not set, ignore this message.");
					return null;
				}

				DHKeyMessage dhKey = new DHKeyMessage();
				in = new ByteArrayInputStream(EncodedMessageUtils
						.decodeMessage(msgText));
				dhKey.readObject(in);

				Boolean replyRevealSig = false;

				switch (auth.getAuthenticationState()) {
				case AWAITING_DHKEY:
					// Computes MB = MACm1(gx, gy, pubB, keyidB)
					logger.info("Computing M");
					KeyPair keyPair = listener.getKeyPair(account, protocol);
					auth.setAuthAwaitingSig(dhKey, keyPair);
					replyRevealSig = true;
					break;
				case AWAITING_SIG:
					if (dhKey.getDhPublicKey().getY().equals(
							auth.getRemoteDHPublicKey().getY())) {
						replyRevealSig = true;
					}
					break;
				default:
					break;
				}

				if (replyRevealSig) {
					RevealSignatureMessage revealSignatureMessage = auth
							.getRevealSignatureMessage();

					logger.info("Sending Reveal Signature.");
					listener.injectMessage(revealSignatureMessage
							.toUnsafeString());
				}
				return null;
			case MessageType.REVEALSIG:
				logger.info(account
						+ " received a reveal signature message from " + user
						+ " throught " + protocol + ".");

				if (!allowV2) {
					logger
							.info("Policy does not allow OTRv2, ignoring message.");
					return null;
				}

				RevealSignatureMessage revealSigMessage = new RevealSignatureMessage();
				in = new ByteArrayInputStream(EncodedMessageUtils
						.decodeMessage(msgText));
				revealSigMessage.readObject(in);

				switch (auth.getAuthenticationState()) {
				case AWAITING_REVEALSIG:
					// Compute our own signature.
					auth.goSecure(revealSigMessage, listener.getKeyPair(
							account, protocol));
					listener.injectMessage(auth.getSignatureMessage()
							.toUnsafeString());

					// Go secure resets auth.
					ctx.goSecure();
					break;
				default:
					break;
				}
				return null;
			case MessageType.SIGNATURE:
				logger.info(account + " received a signature message from "
						+ user + " throught " + protocol + ".");
				if (!allowV2) {
					logger
							.info("Policy does not allow OTRv2, ignoring message.");
					return null;
				}

				SignatureMessage sigMessage = new SignatureMessage();
				in = new ByteArrayInputStream(EncodedMessageUtils
						.decodeMessage(msgText));
				sigMessage.readObject(in);

				switch (auth.getAuthenticationState()) {
				case AWAITING_SIG:
					auth.goSecure(sigMessage);
					ctx.goSecure();
					break;
				default:
					logger
							.info("We were not expecting a signature, ignoring message.");
					return null;
				}
			case MessageType.ERROR:
				logger.info(account + " received an error message from " + user
						+ " throught " + protocol + ".");
				receivingErrorMessage(ctx, listener, new ErrorMessage(msgText));
				break;
			case MessageType.PLAINTEXT:
				logger.info(account + " received a plaintext message from "
						+ user + " throught " + protocol + ".");
				return receivingPlainTextMessage(ctx, listener,
						new PlainTextMessage(msgText));
			case MessageType.QUERY:
				logger.info(account + " received a query message from " + user
						+ " throught " + protocol + ".");
				receivingQueryMessage(ctx, listener, new QueryMessage(msgText));
				logger.info("User needs to know nothing about Query messages.");
				return null;
			case MessageType.V1_KEY_EXCHANGE:
				logger
						.warning("Received V1 key exchange which is not supported.");
				throw new UnsupportedOperationException();
			case MessageType.UKNOWN:
			default:
				logger.warning("Unrecognizable OTR message received.");
				break;
			}

			return msgText;
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Message receiving failed.", e);
			return msgText;
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {
					logger.log(Level.WARNING,
							"Could not close receiving stream.", e);
				}
			}
		}
	}

	private static String receivingDataMessage(ConnContext ctx,
			OTR4jListener listener, DataMessage msg) throws Exception {

		switch (ctx.getMessageState()) {
		case ENCRYPTED:
			logger
					.info("Message state is ENCRYPTED. Trying to decrypt message.");
			MysteriousT t = msg.t;

			// Find matching session keys.
			int senderKeyID = t.senderKeyID;
			int receipientKeyID = t.recipientKeyID;
			SessionKeys matchingKeys = ctx.findSessionKeysByID(receipientKeyID,
					senderKeyID);

			if (matchingKeys == null)
				throw new OtrException("No matching keys found.");

			// Verify received MAC with a locally calculated MAC.
			if (!msg.verify(matchingKeys.getReceivingMACKey()))
				throw new OtrException("MAC verification failed.");

			logger.info("Computed HmacSHA1 value matches sent one.");

			// Mark this MAC key as old to be revealed.
			matchingKeys.setIsUsedReceivingMACKey(true);

			matchingKeys.setReceivingCtr(t.ctr);

			String decryptedMsgContent = t.getDecryptedMessage(matchingKeys
					.getReceivingAESKey(), matchingKeys.getReceivingCtr());
			logger.info("Decrypted message: \"" + decryptedMsgContent + "\"");

			// Rotate keys if necessary.
			ctx.rotateKeys(receipientKeyID, senderKeyID, t.nextDHPublicKey);

			return decryptedMsgContent;
		case FINISHED:
		case PLAINTEXT:
			listener.showWarning("Unreadable encrypted message was received");
			ErrorMessage errormsg = new ErrorMessage("Oups.");
			listener.injectMessage(errormsg.toString());
			break;
		}

		return null;
	}

	private static String receivingPlainTextMessage(ConnContext ctx,
			OTR4jListener listener, PlainTextMessage msg) throws Exception {
		Vector<Integer> versions = msg.versions;
		int policy = listener.getPolicy(ctx);
		if (versions.size() < 1) {
			logger
					.info("Received plaintext message without the whitespace tag.");
			switch (ctx.getMessageState()) {
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
			logger.info("Received plaintext message with the whitespace tag.");
			String cleanText = msg.cleanText;
			switch (ctx.getMessageState()) {
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
				logger.info("WHITESPACE_START_AKE is set");

				if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
					logger.info("V2 tag found, starting v2 AKE.");
					AuthenticationInfo auth = ctx.getAuthenticationInfo();
					auth.reset();
					auth.setAuthAwaitingDHKey();

					logger.info("Sending D-H Commit.");
					listener.injectMessage(auth.getDHCommitMessage()
							.toUnsafeString());
				} else if (versions.contains(1)
						&& PolicyUtils.getAllowV1(policy)) {
					throw new UnsupportedOperationException();
				}
			}
		}

		return null;
	}

	private static void receivingQueryMessage(ConnContext ctx,
			OTR4jListener listener, QueryMessage msg) throws Exception {

		Vector<Integer> versions = msg.versions;
		int policy = listener.getPolicy(ctx);
		if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
			logger
					.info("Query message with V2 support found, starting V2 AKE.");
			AuthenticationInfo auth = ctx.getAuthenticationInfo();
			auth.reset();

			auth.setAuthAwaitingDHKey();

			logger.info("Sending D-H Commit.");
			listener.injectMessage(auth.getDHCommitMessage().toUnsafeString());
		} else if (versions.contains(1) && PolicyUtils.getAllowV1(policy)) {
			throw new UnsupportedOperationException();
		}
	}

	private static void receivingErrorMessage(ConnContext ctx,
			OTR4jListener listener, ErrorMessage msg) {

		listener.showError(msg.error);
		int policy = listener.getPolicy(ctx);
		if (PolicyUtils.getErrorStartsAKE(policy)) {
			logger.info("Error message starts AKE.");
			Vector<Integer> versions = new Vector<Integer>();
			if (PolicyUtils.getAllowV1(policy))
				versions.add(1);

			if (PolicyUtils.getAllowV2(policy))
				versions.add(2);

			QueryMessage queryMessage = new QueryMessage(versions);

			logger.info("Sending Query");
			listener.injectMessage(queryMessage.toString());
		}
	}
}
