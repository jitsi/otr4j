package net.java.otr4j;

import java.io.*;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.logging.*;

import javax.crypto.*;
import javax.crypto.interfaces.*;

import net.java.otr4j.context.*;
import net.java.otr4j.context.auth.*;
import net.java.otr4j.crypto.*;
import net.java.otr4j.message.*;
import net.java.otr4j.message.encoded.*;
import net.java.otr4j.message.encoded.signature.*;
import net.java.otr4j.message.unencoded.*;
import net.java.otr4j.message.unencoded.query.*;

public final class StateMachine {
	private static Logger logger = Logger.getLogger(StateMachine.class
			.getName());

	public static String sendingMessage(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) {
		try {
			return sendingMessageUnsafe(listener, userState, user, account,
					protocol, msgText);
		} catch (Exception e) {
			logger.severe(e.getMessage());
			return msgText;
		}
	}

	private static String sendingMessageUnsafe(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		ConnContext ctx = userState.getConnContext(user, account, protocol);
		logger.info(account + " sends a message to " + user + " throught "
				+ protocol + ".");
		switch (ctx.messageState) {
		case PLAINTEXT:
			logger.info("Message state is PLAINTEXT.");
			logger.warning("State handling not implemented.");
			return msgText;
		case ENCRYPTED:
			logger.info("Message state is ENCRYPTED.");
			ctx.lastSentMessage = msgText;

			logger.info("Getting encryption keys");
			SessionKeys encryptionKeys = ctx.sessionKeys[0][1];
			logger.info("Getting most recent keys.");
			SessionKeys mostRecentKeys = ctx.getMostRecentSessionKeys();
			// Computes TA = (keyidA, keyidB, next_dh, ctr, AES-CTRek,ctr(msg))

			int senderKeyID = encryptionKeys.localKeyID;
			int receipientKeyID = encryptionKeys.remoteKeyID;
			DHPublicKey nextDH = (DHPublicKey) mostRecentKeys.localPair
					.getPublic();
			encryptionKeys.incrementSendingCtr();
			byte[] ctr = encryptionKeys.getSendingCtr();
			byte[] msgBytes = msgText.getBytes();
			logger
					.info("Encrypting message with keyids (localKeyID, remoteKeyID) = ("
							+ senderKeyID + ", " + receipientKeyID + ")");
			byte[] encryptedMsg = CryptoUtils.aesEncrypt(encryptionKeys
					.getSendingAESKey(), ctr, msgBytes);

			logger.info("Getting MAC keys to reveal.");
			byte[] oldMacKeys = ctx.getOldMacKeys();

			MysteriousT t = new MysteriousT(senderKeyID, receipientKeyID,
					nextDH, ctr, encryptedMsg);

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			t.writeObject(out);
			logger.info("Serializing T.");
			byte[] serializedT = out.toByteArray();
			out.close();

			byte[] sendingmackey = encryptionKeys.getSendingMACKey();
			logger.info("Calculating MAC(T).");
			byte[] mac = CryptoUtils.sha1Hmac(serializedT, sendingmackey,
					DataLength.MAC);

			DataMessage msg = new DataMessage(2, 0, t, mac, oldMacKeys);

			logger.info("Injecting message.");
			return msg.toUnsafeString();
		case FINISHED:
			logger.info("Message state is FINISHED.");
			logger.warning("State handling not implemented.");
			return msgText;
		default:
			return msgText;
		}
	}

	public static String receivingMessage(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) {
		try {
			return receivingMessageUnsafe(listener, userState, user, account,
					protocol, msgText);

		} catch (Exception e) {
			logger.severe(e.getMessage());
			return msgText;
		}
	}

	private static String receivingMessageUnsafe(OTR4jListener listener,
			UserState userState, String user, String account, String protocol,
			String msgText) throws NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, SignatureException, IOException {

		if (Utils.IsNullOrEmpty(msgText))
			return msgText;

		ConnContext ctx = userState.getConnContext(user, account, protocol);
		int policy = listener.getPolicy(ctx);

		if (!PolicyUtils.getAllowV1(policy) && !PolicyUtils.getAllowV2(policy)) {
			logger
					.info("Policy does not allow neither V1 not V2, ignoring message.");
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
				|| msgText.startsWith(MessageHeader.DATA2)) {
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
			logger
					.info(account + " received a data message from " + user
							+ ".");
			DataMessage data = new DataMessage();
			data.readObject(new ByteArrayInputStream(EncodedMessageUtils
					.decodeMessage(msgText)));
			return receivingDataMessage(ctx, listener, data);
		case MessageType.DH_COMMIT:
			logger.info(account + " received a D-H commit message from " + user
					+ " throught " + protocol + ".");
			DHCommitMessage dhCommit = new DHCommitMessage();
			dhCommit.readObject(new ByteArrayInputStream(EncodedMessageUtils
					.decodeMessage(msgText)));
			receivingDHCommitMessage(ctx, listener, dhCommit);
			return null;
		case MessageType.DH_KEY:
			logger.info(account + " received a D-H key message from " + user
					+ " throught " + protocol + ".");
			DHKeyMessage dhKey = new DHKeyMessage();
			dhKey.readObject(new ByteArrayInputStream(EncodedMessageUtils
					.decodeMessage(msgText)));
			receivingDHKeyMessage(ctx, listener, dhKey, account, protocol);
			return null;
		case MessageType.REVEALSIG:
			logger.info(account + " received a reveal signature message from "
					+ user + " throught " + protocol + ".");
			RevealSignatureMessage revealSigMessage = new RevealSignatureMessage();
			revealSigMessage.readObject(new ByteArrayInputStream(
					EncodedMessageUtils.decodeMessage(msgText)));
			receivingRevealSignatureMessage(ctx, listener, revealSigMessage,
					account, protocol);
			return null;
		case MessageType.SIGNATURE:
			logger.info(account + " received a signature message from " + user
					+ " throught " + protocol + ".");
			SignatureMessage sigMessage = new SignatureMessage();
			sigMessage.readObject(new ByteArrayInputStream(EncodedMessageUtils
					.decodeMessage(msgText)));
			receivingSignatureMessage(ctx, listener, sigMessage);
			return null;
		case MessageType.ERROR:
			logger.info(account + " received an error message from " + user
					+ " throught " + protocol + ".");
			receivingErrorMessage(ctx, listener, new ErrorMessage(msgText));
			break;
		case MessageType.PLAINTEXT:
			logger.info(account + " received a plaintext message from " + user
					+ " throught " + protocol + ".");
			return receivingPlainTextMessage(ctx, listener,
					new PlainTextMessage(msgText));
		case MessageType.QUERY:
			logger.info(account + " received a query message from " + user
					+ " throught " + protocol + ".");
			receivingQueryMessage(ctx, listener, new QueryMessage(msgText));
			logger.info("User needs to know nothing about Query messages.");
			return null;
		case MessageType.V1_KEY_EXCHANGE:
			logger.warning("Received V1 key exchange which is not supported.");
			throw new UnsupportedOperationException();
		case MessageType.UKNOWN:
		default:
			logger.warning("Unrecognizable OTR message received.");
			break;
		}

		return msgText;
	}

	private static String receivingDataMessage(ConnContext ctx,
			OTR4jListener listener, DataMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException, IOException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, InvalidKeySpecException {

		switch (ctx.messageState) {
		case ENCRYPTED:
			logger
					.info("Message state is ENCRYPTED. Trying to decrypt message.");
			MysteriousT t = msg.t;
			int senderKeyID = t.senderKeyID;
			int receipientKeyID = t.recipientKeyID;

			SessionKeys matchingKeys = ctx.findSessionKeysByID(receipientKeyID,
					senderKeyID);

			if (matchingKeys == null) {
				logger.severe("No matching keys found!!!");
				return "OTR Error: No matching keys found.";
			}

			logger.info("Transforming T to byte[] to calculate it's HmacSHA1.");
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			t.writeObject(out);
			byte[] serializedT = out.toByteArray();
			out.close();

			byte[] receivingmackey = matchingKeys.getReceivingMACKey();
			byte[] computedMAC = CryptoUtils.sha1Hmac(serializedT,
					receivingmackey, DataLength.MAC);

			if (!Arrays.equals(computedMAC, msg.getMac())) {
				logger.severe("MAC verification failed.");
				return "OTR Error: MAC verification failed.";
			}

			logger.info("Computed HmacSHA1 value matches sent one.");
			matchingKeys.setIsUsedReceivingMACKey(true);

			matchingKeys.setReceivingCtr(t.ctr);

			byte[] decryptedMsg = CryptoUtils.aesDecrypt(matchingKeys
					.getReceivingAESKey(), matchingKeys.getReceivingCtr(),
					t.encryptedMsg);
			String decryptedMsgContent = new String(decryptedMsg);
			logger.info("Decrypted message: \"" + decryptedMsgContent + "\"");

			SessionKeys mostRecent = ctx.getMostRecentSessionKeys();
			if (mostRecent.localKeyID == receipientKeyID)
				ctx.rotateLocalKeys();

			if (mostRecent.remoteKeyID == senderKeyID)
				ctx.rotateRemoteKeys(t.nextDHPublicKey);

			return decryptedMsgContent;
		case FINISHED:
		case PLAINTEXT:
			listener.showWarning("unreadable encrypted message was received");
			ErrorMessage errormsg = new ErrorMessage("Oups.");
			listener.injectMessage(errormsg.toString());
			break;
		}

		return null;
	}

	private static void receivingSignatureMessage(ConnContext ctx,
			OTR4jListener listener, SignatureMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException, IOException, SignatureException,
			NoSuchProviderException {

		int policy = listener.getPolicy(ctx);
		if (!PolicyUtils.getAllowV2(policy)) {
			logger.info("Policy does not allow OTRv2, ignoring message.");
			return;
		}

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.getAuthenticationState()) {
		case AWAITING_SIG:
			// Uses m2' to verify MACm2'(AESc'(XA))
			byte[] remoteXEncrypted = msg.getXEncrypted();

			ByteArrayOutputStream out_ = new ByteArrayOutputStream();
			SerializationUtils.writeData(out_, remoteXEncrypted);
			byte[] tmp_ = out_.toByteArray();
			out_.close();

			byte[] remoteXEncryptedMAC = CryptoUtils.sha256Hmac160(tmp_, auth
					.getM2p());
			if (!Arrays.equals(remoteXEncryptedMAC, msg.getXEncryptedMAC())) {
				logger.info("Signature MACs are not equal, ignoring message.");
				return;
			}

			// Uses c' to decrypt AESc'(XA) to obtain XA = pubA, keyidA,
			// sigA(MA)
			byte[] remoteXDecrypted = CryptoUtils.aesDecrypt(auth.getCp(),
					null, remoteXEncrypted);

			// Computes MA = MACm1'(gy, gx, pubA, keyidA)
			MysteriousX remoteX = new MysteriousX();
			remoteX.readObject(new ByteArrayInputStream(remoteXDecrypted));
			auth.setRemoteDHPPublicKeyID(remoteX.getDhKeyID());
			MysteriousM remoteM = new MysteriousM(auth.getM1p(), auth
					.getRemoteDHPublicKey(), (DHPublicKey) auth
					.getLocalDHKeyPair().getPublic(), remoteX
					.getLongTermPublicKey(), remoteX.getDhKeyID());

			// Uses pubA to verify sigA(MA)
			if (!CryptoUtils.verify(remoteM.compute(), remoteX
					.getLongTermPublicKey(), remoteX.getSignature())) {
				logger.severe("Signature verification failed.");
				return;
			}
			logger.info("Signature verification succeeded.");

			goSecure(ctx, auth.getLocalDHKeyPair(),
					auth.getRemoteDHPublicKey(), auth.getS());
			break;
		default:
			logger.info("We were not expecting a signature, ignoring message.");
			break;
		}

	}

	private static void receivingRevealSignatureMessage(ConnContext ctx,
			OTR4jListener listener, RevealSignatureMessage msg, String account,
			String protocol) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, SignatureException, InvalidKeySpecException,
			IOException, NoSuchProviderException {

		int policy = listener.getPolicy(ctx);
		if (!PolicyUtils.getAllowV2(policy)) {
			logger.info("Policy does not allow OTRv2, ignoring message.");
			return;
		}

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.getAuthenticationState()) {
		case AWAITING_REVEALSIG:
			// Uses r to decrypt the value of gx sent earlier
			byte[] revealedKey = msg.getRevealedKey();
			byte[] remoteDHPublicKeyDecrypted = CryptoUtils.aesDecrypt(
					revealedKey, null, auth.getRemoteDHPublicKeyEncrypted());

			// Verifies that HASH(gx) matches the value sent earlier
			byte[] remoteDHPublicKeyHash = CryptoUtils
					.sha256Hash(remoteDHPublicKeyDecrypted);
			if (!Arrays.equals(remoteDHPublicKeyHash, auth
					.getRemoteDHPublicKeyHash())) {
				logger.info("Hashes don't match, ignoring message.");
				return;
			}

			// Verifies that Bob's gx is a legal value (2 <= gx <= modulus-2)
			ByteArrayInputStream inmpi = new ByteArrayInputStream(
					remoteDHPublicKeyDecrypted);
			BigInteger remoteDHPublicKeyMpi = DeserializationUtils
					.readMpi(inmpi);
			if (remoteDHPublicKeyMpi
					.compareTo(CryptoConstants.MODULUS_MINUS_TWO) > 0) {
				logger.info("gx <= modulus-2, ignoring message.");
				return;
			} else if (remoteDHPublicKeyMpi
					.compareTo(CryptoConstants.BIGINTEGER_TWO) < 0) {
				logger.info("2 <= gx, ignoring message.");
				return;
			}

			auth.setRemoteDHPublicKey(CryptoUtils
					.getDHPublicKey(remoteDHPublicKeyMpi));

			// Computes s = (gx)y (note that this will be the same as the value
			// of s Bob calculated)
			// Computes two AES keys c, c' and four MAC keys m1, m1', m2, m2' by
			// hashing s in various ways (the same as Bob)
			BigInteger s = auth.getS();

			// Uses m2 to verify MACm2(AESc(XB))
			byte[] remoteXEncrypted = msg.getXEncrypted();

			ByteArrayOutputStream out_ = new ByteArrayOutputStream();
			SerializationUtils.writeData(out_, remoteXEncrypted);
			byte[] tmp_ = out_.toByteArray();
			out_.close();

			byte[] remoteXEncryptedMAC = CryptoUtils.sha256Hmac160(tmp_, auth
					.getM2());
			if (!Arrays.equals(remoteXEncryptedMAC, msg.getXEncryptedMAC())) {
				logger.info("Signature MACs are not equal, ignoring message.");
				return;
			}

			// Uses c to decrypt AESc(XB) to obtain XB = pubB, keyidB, sigB(MB)
			byte[] remoteXDecrypted = CryptoUtils.aesDecrypt(auth.getC(), null,
					remoteXEncrypted);

			MysteriousX remoteX = new MysteriousX();
			remoteX.readObject(new ByteArrayInputStream(remoteXDecrypted));
			auth.setRemoteDHPPublicKeyID(remoteX.getDhKeyID());

			// Computes MB = MACm1(gx, gy, pubB, keyidB)
			MysteriousM remoteM = new MysteriousM(auth.getM1(), auth
					.getRemoteDHPublicKey(), (DHPublicKey) auth
					.getLocalDHKeyPair().getPublic(), remoteX
					.getLongTermPublicKey(), remoteX.getDhKeyID());

			// Uses pubB to verify sigB(MB)
			if (!CryptoUtils.verify(remoteM.compute(), remoteX
					.getLongTermPublicKey(), remoteX.getSignature())) {
				logger.severe("Signature verification failed.");
				return;
			}
			logger.info("Signature verification succeeded.");

			// Computes MA = MACm1'(gy, gx, pubA, keyidA)
			auth
					.setLocalLongTermKeyPair(listener.getKeyPair(account,
							protocol));
			logger.info("Calculating our M and our X.");
			DHPublicKey localDHPublicKey = (DHPublicKey) auth
					.getLocalDHKeyPair().getPublic();
			MysteriousM localM = new MysteriousM(auth.getM1p(),
					localDHPublicKey, auth.getRemoteDHPublicKey(), auth
							.getLocalLongTermKeyPair().getPublic(), auth
							.getLocalDHKeyPairID());

			byte[] localSignature = CryptoUtils.sign(localM.compute(), auth
					.getLocalLongTermKeyPair().getPrivate());

			// Computes XA = pubA, keyidA, sigA(MA)
			MysteriousX localX = new MysteriousX(auth.getLocalLongTermKeyPair()
					.getPublic(), auth.getLocalDHKeyPairID(), localSignature);

			ByteArrayOutputStream localXbos = new ByteArrayOutputStream();
			localX.writeObject(localXbos);
			byte[] localXbytes = localXbos.toByteArray();

			// Sends Bob AESc'(XA), MACm2'(AESc'(XA))
			auth.setLocalXEncrypted(CryptoUtils.aesEncrypt(auth.getCp(), null,
					localXbytes));

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			SerializationUtils.writeData(out, auth.getLocalXEncrypted());
			byte[] tmp = out.toByteArray();
			out.close();

			auth.setLocalXEncryptedMac(CryptoUtils.sha256Hmac160(tmp, auth
					.getM2p()));

			SignatureMessage msgSig = new SignatureMessage(2, auth
					.getLocalXEncryptedMac(), auth.getLocalXEncrypted());

			goSecure(ctx, auth.getLocalDHKeyPair(),
					auth.getRemoteDHPublicKey(), s);

			String msgText = msgSig.toUnsafeString();
			listener.injectMessage(msgText);
			break;
		default:
			break;
		}
	}

	private static void goSecure(ConnContext ctx, KeyPair keyPair,
			DHPublicKey pubKey, BigInteger s) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeySpecException {

		logger.info("Setting most recent session keys from auth.");
		for (int i = 0; i < ctx.sessionKeys[0].length; i++) {
			SessionKeys current = ctx.sessionKeys[0][i];
			current.setLocalPair(keyPair, 1);
			current.setRemoteDHPublicKey(pubKey, 1);
			current.setS(s);
		}

		KeyPair nextDH = CryptoUtils.generateDHKeyPair();
		for (int i = 0; i < ctx.sessionKeys[1].length; i++) {
			SessionKeys current = ctx.sessionKeys[1][i];
			current.setRemoteDHPublicKey(pubKey, 1);
			current.setLocalPair(nextDH, 2);
		}

		ctx.authenticationInfo.reset();
		ctx.messageState = MessageState.ENCRYPTED;
		logger.info("Gone Secure.");
	}

	private static String receivingPlainTextMessage(ConnContext ctx,
			OTR4jListener listener, PlainTextMessage msg)
			throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, IOException, InvalidKeySpecException {
		Vector<Integer> versions = msg.versions;
		int policy = listener.getPolicy(ctx);
		if (versions.size() < 1) {
			logger
					.info("Received plaintext message without the whitespace tag.");
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
			logger.info("Received plaintext message with the whitespace tag.");
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
				logger.info("WHITESPACE_START_AKE is set");

				if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
					logger.info("V2 tag found, starting v2 AKE.");
					AuthenticationInfo auth = ctx.authenticationInfo;
					auth.reset();

					DHCommitMessage dhCommitMessage = new DHCommitMessage(2,
							auth.getLocalDHPublicKeyHash(), auth
									.getLocalDHPublicKeyEncrypted());
					auth
							.setAuthenticationState(AuthenticationState.AWAITING_DHKEY);

					logger.info("Sending D-H Commit.");
					listener.injectMessage(dhCommitMessage.toUnsafeString());
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
			NoSuchProviderException, IOException, InvalidKeySpecException {

		Vector<Integer> versions = msg.versions;
		int policy = listener.getPolicy(ctx);
		if (versions.contains(2) && PolicyUtils.getAllowV2(policy)) {
			logger
					.info("Query message with V2 support found, starting V2 AKE.");
			AuthenticationInfo auth = ctx.authenticationInfo;
			auth.reset();

			DHCommitMessage dhCommitMessage = new DHCommitMessage(2, auth
					.getLocalDHPublicKeyHash(), auth
					.getLocalDHPublicKeyEncrypted());
			auth.setAuthenticationState(AuthenticationState.AWAITING_DHKEY);

			logger.info("Sending D-H Commit.");
			listener.injectMessage(dhCommitMessage.toUnsafeString());
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

	private enum ReceivingDHCommitMessageActions {
		RETRANSMIT_OLD_DH_KEY, SEND_NEW_DH_KEY, RETRANSMIT_DH_COMMIT,
	}

	private static void receivingDHCommitMessage(ConnContext ctx,
			OTR4jListener listener, DHCommitMessage msg)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, IOException,
			InvalidKeySpecException {

		if (!PolicyUtils.getAllowV2(listener.getPolicy(ctx))) {
			logger.info("ALLOW_V2 is not set, ignore this message.");
			return;
		}

		// Set SEND_DH_KEY as default action.
		ReceivingDHCommitMessageActions action = ReceivingDHCommitMessageActions.SEND_NEW_DH_KEY;

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.getAuthenticationState()) {
		case NONE:
			action = ReceivingDHCommitMessageActions.SEND_NEW_DH_KEY;
			break;

		case AWAITING_DHKEY:
			BigInteger ourHash = new BigInteger(auth.getLocalDHPublicKeyHash())
					.abs();
			BigInteger theirHash = new BigInteger(msg.getDhPublicKeyHash())
					.abs();

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
					.info("Ignore the incoming D-H Commit message, but resend your D-H Commit message.");
			DHCommitMessage dhCommit = new DHCommitMessage(2, auth
					.getLocalDHPublicKeyHash(), auth
					.getLocalDHPublicKeyEncrypted());

			logger.info("Sending D-H Commit.");
			listener.injectMessage(dhCommit.toUnsafeString());
			break;
		case SEND_NEW_DH_KEY:
			auth.reset();
		case RETRANSMIT_OLD_DH_KEY:
			auth.setRemoteDHPublicKeyEncrypted(msg.getDhPublicKeyEncrypted());
			auth.setRemoteDHPublicKeyHash(msg.getDhPublicKeyHash());

			DHKeyMessage dhKey = new DHKeyMessage(2, (DHPublicKey) auth
					.getLocalDHKeyPair().getPublic());
			auth.setAuthenticationState(AuthenticationState.AWAITING_REVEALSIG);

			logger.info("Sending D-H key.");
			listener.injectMessage(dhKey.toUnsafeString());
		default:
			break;
		}
	}

	private static void receivingDHKeyMessage(ConnContext ctx,
			OTR4jListener listener, DHKeyMessage msg, String account,
			String protocol) throws InvalidKeyException,
			NoSuchAlgorithmException, SignatureException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, IOException,
			NoSuchProviderException, InvalidKeySpecException {

		if (!PolicyUtils.getAllowV2(listener.getPolicy(ctx))) {
			logger.info("If ALLOW_V2 is not set, ignore this message.");
			return;
		}

		Boolean replyRevealSig = false;

		AuthenticationInfo auth = ctx.authenticationInfo;
		switch (auth.getAuthenticationState()) {
		case AWAITING_DHKEY:
			// Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)
			if (msg.getDhPublicKey().getY().compareTo(
					CryptoConstants.MODULUS_MINUS_TWO) > 0) {
				logger.info("Illegal D-H Public Key value, Ignoring message.");
				return;
			} else if (msg.getDhPublicKey().getY().compareTo(
					CryptoConstants.BIGINTEGER_TWO) < 0) {
				logger.info("Illegal D-H Public Key value, Ignoring message.");
				return;
			}
			logger.info("Received D-H Public Key is a legal value.");

			// Computes s = (gy)x
			auth.setRemoteDHPublicKey(msg.getDhPublicKey());

			// Computes MB = MACm1(gx, gy, pubB, keyidB)
			logger.info("Computing M");
			KeyPair keyPair = listener.getKeyPair(account, protocol);
			auth.setLocalLongTermKeyPair(keyPair);

			DHPublicKey ourDHPublicKey = (DHPublicKey) auth.getLocalDHKeyPair()
					.getPublic();
			MysteriousM m = new MysteriousM(auth.getM1(), ourDHPublicKey, auth
					.getRemoteDHPublicKey(), auth.getLocalLongTermKeyPair()
					.getPublic(), auth.getLocalDHKeyPairID());

			byte[] mbytes = m.compute();
			byte[] signature = CryptoUtils.sign(mbytes, auth
					.getLocalLongTermKeyPair().getPrivate());

			// Computes XB = pubB, keyidB, sigB(MB)
			logger.info("Computing X");
			MysteriousX x = new MysteriousX(auth.getLocalLongTermKeyPair()
					.getPublic(), auth.getLocalDHKeyPairID(), signature);

			ByteArrayOutputStream xstream = new ByteArrayOutputStream();
			x.writeObject(xstream);
			byte[] xbytes = xstream.toByteArray();

			// Sends Alice r, AESc(XB), MACm2(AESc(XB))
			auth.setLocalXEncrypted(CryptoUtils.aesEncrypt(auth.getC(), null,
					xbytes));

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			SerializationUtils.writeData(out, auth.getLocalXEncrypted());
			byte[] tmp = out.toByteArray();
			out.close();

			byte[] localXEncryptedMac = CryptoUtils.sha256Hmac160(tmp, auth
					.getM2());
			auth.setLocalXEncryptedMac(localXEncryptedMac);

			replyRevealSig = true;
			break;
		case AWAITING_SIG:
			if (msg.getDhPublicKey().getY().equals(
					auth.getRemoteDHPublicKey().getY())) {
				replyRevealSig = true;
			}
			break;
		default:
			break;
		}

		if (replyRevealSig) {
			int protocolVersion = 2;

			RevealSignatureMessage revealSignatureMessage = new RevealSignatureMessage(
					protocolVersion, auth.getR(), auth.getLocalXEncryptedMac(),
					auth.getLocalXEncrypted());

			auth.setAuthenticationState(AuthenticationState.AWAITING_SIG);
			logger.info("Sending Reveal Signature.");
			listener.injectMessage(revealSignatureMessage.toUnsafeString());
		}

	}
}
