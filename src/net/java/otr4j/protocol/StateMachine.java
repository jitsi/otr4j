package net.java.otr4j.protocol;

import java.util.Vector;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.message.*;
import net.java.otr4j.message.encoded.*;
import net.java.otr4j.message.unencoded.*;

/**
 * <pre>
 * State transitions
 * 
 * There are thirteen actions an OTR client must handle:
 * 
 * Received messages:
 *           o Plaintext without the whitespace tag
 *           o Plaintext with the whitespace tag
 *           o Query Message
 *           o Error Message
 *           o D-H Commit Message
 *           o D-H Key Message
 *           o Reveal Signature Message
 *           o Signature Message
 *           o Version 1 Key Exchange Message
 *           o Data Message
 * User actions:
 *           o User requests to start an OTR conversation
 *           o User requests to end an OTR conversation
 *           o User types a message to be sent
 * 
 * If neither ALLOW_V1 nor ALLOW_V2 is set, then OTR is completely disabled, and no special handling of messages should be done at all.
 * </pre>
 * 
 * @author george
 * 
 */
public final class StateMachine {

	private static Boolean getAllowV1(int policy) {
		return (policy & Policy.ALLOW_V1) != 0;
	}

	private static Boolean getAllowV2(int policy) {
		return (policy & Policy.ALLOW_V2) != 0;
	}

	private static Boolean getRequireEncryption(int policy) {
		return (policy & Policy.REQUIRE_ENCRYPTION) != 0;
	}

	private static Boolean getWhiteSpaceStartsAKE(int policy) {
		return (policy & Policy.WHITESPACE_START_AKE) != 0;
	}

	private static Boolean getErrorStartsAKE(int policy) {
		return (policy & Policy.ERROR_START_AKE) != 0;
	}

	public static Boolean receivingMessage(OTR4jListener listener, UserState userState, String user, String account, String protocol, String msgText)
			throws MessageDisassembleException, MessageCreateException {

		ConnContext ctx = userState.getConnContext(user, account, protocol);
		int policy = listener.getPolicy(ctx);

		Boolean bubble = true;
		if (!getAllowV1(policy) && !getAllowV2(policy)) {
			return bubble;
		}

		if (msgText.startsWith(MessageHeader.QUERY1) || msgText.startsWith(MessageHeader.QUERY2)) {
			receivingQueryMessage(ctx, listener, QueryMessage.disassemble(msgText));
			// User needs to know nothing about Query messages.
			bubble = false;
		} else if (msgText.startsWith(MessageHeader.DH_COMMIT)) {
			receivingDHCommitMessage(ctx, DHCommitMessage.disassemble(msgText));
		} else if (msgText.startsWith(MessageHeader.DH_KEY)) {
			DHKeyMessage dhKeyMessage;
			dhKeyMessage = DHKeyMessage.disassemble(msgText);
			receivingDHKeyMessage(ctx, dhKeyMessage);
		} else if (msgText.startsWith(MessageHeader.REVEALSIG)) {
			receivingRevealSignatureMessage(ctx, RevealSignatureMessage.disassemble(msgText));
		} else if (msgText.startsWith(MessageHeader.SIGNATURE)) {
			receivingSignatureMessage(ctx, SignatureMessage.disassemble(msgText));
		} else if (msgText.startsWith(MessageHeader.V1_KEY_EXCHANGE)) {
			receivingV1KeyExchangeMessage(ctx, V1KeyExchange.disassemble(msgText));
		} else if (msgText.startsWith(MessageHeader.DATA1) || msgText.startsWith(MessageHeader.DATA1)) {
			receivingDataMessage(ctx, DataMessage.disassemble(msgText));
		} else if (msgText.startsWith(MessageHeader.ERROR)) {
			receivingErrorMessage(ctx, listener, ErrorMessage.disassemble(msgText));
			// User needs to know nothing about Query messages.
			bubble = false;
		} else {
			PlainTextMessage plainTextMessage = PlainTextMessage.disassemble(msgText);
			bubble = receivingPlainTextMessage(ctx, listener, plainTextMessage);
		}

		return bubble;
	}

	/**
	 * <pre>
	 * Receiving a Version 1 Key Exchange Message
	 *
	 * If ALLOW_V1 is not set, ignore this message. Otherwise:
	 *
	 * If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_DHKEY, AUTHSTATE_AWAITING_REVEALSIG, or AUTHSTATE_AWAITING_SIG:
	 *
	 *     If the reply field is not set to 0x01:
	 *         Verify the information in the Key Exchange Message. If the verification succeeds:
	 *
	 * Reply with a Key Exchange Message with the reply field set to 0x01.
	 * Transition authstate to AUTHSTATE_NONE.
	 * Transition msgstate to MSGSTATE_ENCRYPTED.
	 * If there is a recent stored message, encrypt it and send it as a Data Message.
	 *
	 *         Otherwise, ignore the message.
	 *     Otherwise, ignore the message.
	 *
	 * If authstate is AUTHSTATE_V1_SETUP:
	 *     Verify the information in the Key Exchange Message. If the verification succeeds:
	 *
	 * If the received Key Exchange Message did not have the reply field set to 0x01, reply with a Key Exchange Message with the reply field set to 0x01.
	 * Transition authstate to AUTHSTATE_NONE.
	 * Transition msgstate to MSGSTATE_ENCRYPTED.
	 * If there is a recent stored message, encrypt it and send it as a Data Message.
	 *
	 *     Otherwise, ignore the message.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 */
	private static void receivingV1KeyExchangeMessage(ConnContext ctx, V1KeyExchange msg) {
		// TODO Auto-generated method stub
	}

	/**
	 * <pre>
	 * Receiving plaintext without the whitespace tag
	 *
	 * If msgstate is MSGSTATE_PLAINTEXT:
	 *     Simply display the message to the user. If REQUIRE_ENCRYPTION is set, warn him that the message was received unencrypted.
	 * If msgstate is MSGSTATE_ENCRYPTED or MSGSTATE_FINISHED:
	 *     Display the message to the user, but warn him that the message was received unencrypted.
	 * </pre>
	 *
	 * <pre>
	 * Receiving plaintext with the whitespace tag
	 *
	 * If msgstate is MSGSTATE_PLAINTEXT:
	 *     Remove the whitespace tag and display the message to the user. If REQUIRE_ENCRYPTION is set, warn him that the message was received unencrypted.
	 * If msgstate is MSGSTATE_ENCRYPTED or MSGSTATE_FINISHED:
	 *     Remove the whitespace tag and display the message to the user, but warn him that the message was received unencrypted.
	 *
	 * In any event, if WHITESPACE_START_AKE is set:
	 *
	 * If the tag offers OTR version 2 and ALLOW_V2 is set:
	 *     Send a D-H Commit Message, and transition authstate to AUTHSTATE_AWAITING_DHKEY.
	 * Otherwise, if the tag offers OTR version 1 and ALLOW_V1 is set:
	 *     Send a Version 1 Key Exchange Message, and transition authstate to AUTHSTATE_V1_SETUP.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 * @throws MessageCreateException
	 */
	private static Boolean receivingPlainTextMessage(ConnContext ctx, OTR4jListener listener, PlainTextMessage msg)
			throws MessageCreateException {
		Boolean bubble = true;
		Vector<Integer> versions = msg.getVersions();
		int policy = listener.getPolicy(ctx);
		if (versions.size() < 1) {
			// plaintext without the whitespace tag
			switch (ctx.messageState) {
				case ENCRYPTED:
				case FINISHED:
					// Display the message to the user, but warn him that the
					// message was received unencrypted.
					listener.showWarning("The message was received unencrypted.");
					break;
				case PLAINTEXT:
					// Simply display the message to the user. If REQUIRE_ENCRYPTION
					// is set, warn him that the message was received unencrypted.
					break;
			}
		} else {
			// plaintext with the whitespace tag
			String cleanText = msg.getCleanText();
			switch (ctx.messageState) {
				case ENCRYPTED:
				case FINISHED:
					// Remove the whitespace tag and display the message to the
					// user,
					// but warn him that the message was received unencrypted.
					bubble = false;
					listener.injectMessage(cleanText);
					listener.showWarning("The message was received unencrypted.");
					break;
				case PLAINTEXT:
					// Remove the whitespace tag and display the message to the
					// user. If REQUIRE_ENCRYPTION is set, warn him that the message
					// was received unencrypted.
					bubble = false;
					listener.injectMessage(msg.getCleanText());
					if (getRequireEncryption(policy)) {
						listener.showWarning("The message was received unencrypted.");
					}
					break;
			}

			if (getWhiteSpaceStartsAKE(policy)) {
				// In any event, if WHITESPACE_START_AKE is set
				if (versions.contains(2) && getAllowV2(policy)) {
					// Send a D-H Commit Message, and transition authstate to
					// AUTHSTATE_AWAITING_DHKEY.
					byte[] r = null;
					DHPublicKey gxKey = null;
					DHCommitMessage dhCommit = DHCommitMessage.create(2, r,
							gxKey);
					listener.injectMessage(DHCommitMessage.assemble(dhCommit));
					ctx.authenticationState = AuthenticationState.AWAITING_DHKEY;
				} else if (versions.contains(1) && getAllowV1(policy)) {
					// Send a Version 1 Key Exchange Message, and transition
					// authstate to AUTHSTATE_V1_SETUP.
					// TODO Implement.
				}
			}
		}

		return bubble;
	}

	/**
	 * <pre>
	 * Receiving a Signature Message
	 *
	 * If ALLOW_V2 is not set, ignore this message. Otherwise:
	 *
	 * If authstate is AUTHSTATE_AWAITING_SIG:
	 *     Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:
	 *
	 * Transition authstate to AUTHSTATE_NONE.
	 * Transition msgstate to MSGSTATE_ENCRYPTED.
	 * If there is a recent stored message, encrypt it and send it as a Data Message.
	 *
	 *     Otherwise, ignore the message.
	 * If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_DHKEY, AUTHSTATE_AWAITING_REVEALSIG, or AUTHSTATE_V1_SETUP:
	 *     Ignore the message.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 */
	private static void receivingSignatureMessage(ConnContext ctx, SignatureMessage msg) {
		// TODO Auto-generated method stub
	}

	/**
	 * <pre>
	 * Receiving a Reveal Signature Message
	 *
	 * If ALLOW_V2 is not set, ignore this message. Otherwise:
	 *
	 * If authstate is AUTHSTATE_AWAITING_REVEALSIG:
	 *     Use the received value of r to decrypt the value of gx received in the D-H Commit Message, and verify the hash therein. Decrypt the encrypted signature, and verify the signature and the MACs. If everything checks out:
	 *
	 * Reply with a Signature Message.
	 * Transition authstate to AUTHSTATE_NONE.
	 * Transition msgstate to MSGSTATE_ENCRYPTED.
	 * If there is a recent stored message, encrypt it and send it as a Data Message.
	 *
	 *     Otherwise, ignore the message.
	 * If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_DHKEY, AUTHSTATE_AWAITING_SIG, or AUTHSTATE_V1_SETUP:
	 *     Ignore the message.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 */
	private static void receivingRevealSignatureMessage(ConnContext ctx,
			RevealSignatureMessage msg) {
		// TODO Auto-generated method stub
	}

	/**
	 * <pre>
	 * Receiving a Query Message
	 *
	 * If the Query Message offers OTR version 2 and ALLOW_V2 is set:
	 *     Send a D-H Commit Message, and transition authstate to AUTHSTATE_AWAITING_DHKEY.
	 * Otherwise, if the message offers OTR version 1 and ALLOW_V1 is set:
	 *     Send a Version 1 Key Exchange Message, and transition authstate to AUTHSTATE_V1_SETUP.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 * @throws MessageCreateException
	 */
	private static void receivingQueryMessage(ConnContext ctx, OTR4jListener listener, QueryMessage msg)
			throws MessageCreateException {
		Vector<Integer> versions = msg.getVersions();
		int policy = listener.getPolicy(ctx);
		if (versions.contains(2) && getAllowV2(policy)) {
			byte[] r = null;
			DHPublicKey gxKey = null;
			DHCommitMessage dhCommitMessage = DHCommitMessage.create(2, r,
					gxKey);
			listener.injectMessage(DHCommitMessage.assemble(dhCommitMessage));
		} else if (versions.contains(1) && getAllowV1(policy)) {
			// TODO Implement
		}
	}

	/**
	 * <pre>
	 * Receiving an Error Message
	 *
	 * Display the message to the user. If ERROR_START_AKE is set, reply with a Query Message.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 */
	private static void receivingErrorMessage(ConnContext ctx, OTR4jListener listener, ErrorMessage msg) {
		listener.showError(msg.getError());
		int policy = listener.getPolicy(ctx);
		if (getErrorStartsAKE(policy)) {
			Vector<Integer> versions = new Vector<Integer>();
			if (getAllowV1(policy)) {
				versions.add(1);
			}
			if (getAllowV2(policy)) {
				versions.add(2);
			}
			QueryMessage queryMessage = QueryMessage.create(versions);
			listener.injectMessage(QueryMessage.assemble(queryMessage));
		}
	}

	/**
	 * <pre>
	 * Receiving a D-H Key Message
	 *
	 * If ALLOW_V2 is not set, ignore this message. Otherwise:
	 *
	 * If authstate is AUTHSTATE_AWAITING_DHKEY:
	 *     Reply with a Reveal Signature Message and transition authstate to AUTHSTATE_AWAITING_SIG.
	 * If authstate is AUTHSTATE_AWAITING_SIG:
	 *
	 *     If this D-H Key message is the same the one you received earlier (when you entered AUTHSTATE_AWAITING_SIG):
	 *         Retransmit your Reveal Signature Message.
	 *     Otherwise:
	 *         Ignore the message.
	 *
	 * If authstate is AUTHSTATE_NONE, AUTHSTATE_AWAITING_REVEALSIG, or AUTHSTATE_V1_SETUP:
	 *     Ignore the message.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 */
	private static void receivingDHKeyMessage(ConnContext ctx, DHKeyMessage msg) {
		// TODO Auto-generated method stub
	}

	/**
	 * <pre>
	 * Receiving a D-H Commit Message
	 *
	 * If ALLOW_V2 is not set, ignore this message. Otherwise:
	 *
	 * If authstate is AUTHSTATE_NONE:
	 *     Reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
	 * If authstate is AUTHSTATE_AWAITING_DHKEY:
	 *     This is the trickiest transition in the whole protocol. It indicates that you have already sent a D-H Commit message to your correspondent, but that he either didn't receive it, or just didn't receive it yet, and has sent you one as well. The symmetry will be broken by comparing the hashed gx you sent in your D-H Commit Message with the one you received, considered as 32-byte unsigned big-endian values.
	 *
	 *     If yours is the higher hash value:
	 *         Ignore the incoming D-H Commit message, but resend your D-H Commit message.
	 *     Otherwise:
	 *         Forget your old gx value that you sent (encrypted) earlier, and pretend you're in AUTHSTATE_NONE; i.e. reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
	 *
	 * If authstate is AUTHSTATE_AWAITING_REVEALSIG:
	 *     Retransmit your D-H Key Message (the same one as you sent when you entered AUTHSTATE_AWAITING_REVEALSIG). Forget the old D-H Commit message, and use this new one instead. There are a number of reasons this might happen, including:
	 *
	 * Your correspondent simply started a new AKE.
	 * Your correspondent resent his D-H Commit message, as specified above.
	 * On some networks, like AIM, if your correspondent is logged in multiple times, each of his clients will send a D-H Commit Message in response to a Query Message; resending the same D-H Key Message in response to each of those messages will prevent compounded confusion, since each of his clients will see each of the D-H Key Messages you send. [And the problem gets even worse if you are each logged in multiple times.]
	 *
	 * If authstate is AUTHSTATE_AWAITING_SIG or AUTHSTATE_V1_SETUP:
	 *     Reply with a new D-H Key message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG.
	 * </pre>
	 *
	 * @param userState
	 * @param msg
	 */
	private static Boolean receivingDHCommitMessage(ConnContext ctx, DHCommitMessage msg) {
		Boolean bubble = true;
		switch (ctx.authenticationState) {
			case NONE:
				break;
			case AWAITING_DHKEY:
				break;
			case AWAITING_REVEALSIG:
				break;
			case AWAITING_SIG:
			case V1_SETUP:
				break;
		}

		return bubble;
	}

	private static void receivingDataMessage(ConnContext ctx, DataMessage msg) {
		// TODO Auto-generated method stub
	}
}
