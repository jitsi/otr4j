/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

import org.bouncycastle.util.encoders.Base64;


/**
 * 
 * @author George Politis
 */
public class MessageUtils implements MessageConstants {
	public static int getMessageType(String msgText) {
		int msgType = 0;
		if (!msgText.startsWith(BASE_HEAD)) {
			msgType = PLAINTEXT;
		} else if (msgText.startsWith(DH_COMMIT_HEAD)) {
			msgType = DH_COMMIT;
		} else if (msgText.startsWith(DH_KEY_HEAD)) {
			msgType = DH_KEY;
		} else if (msgText.startsWith(REVEALSIG_HEAD)) {
			msgType = REVEALSIG;
		} else if (msgText.startsWith(SIGNATURE_HEAD)) {
			msgType = SIGNATURE;
		} else if (msgText.startsWith(V1_KEY_EXCHANGE_HEAD)) {
			msgType = V1_KEY_EXCHANGE;
		} else if (msgText.startsWith(DATA1_HEAD)
				|| msgText.startsWith(DATA2_HEAD)) {
			msgType = DATA;
		} else if (msgText.startsWith(ERROR_HEAD)) {
			msgType = ERROR;
		} else if (msgText.startsWith(QUERY1_HEAD)
				|| msgText.startsWith(QUERY2_HEAD)) {
			msgType = QUERY;
		} else {
			msgType = UKNOWN;
		}

		return msgType;
	}
	
	public static byte[] decodeMessage(String msg) {
		int end = msg.lastIndexOf(".");

		if (msg.indexOf(MessageConstants.ENCODED_MESSAGE_HEAD) != 0
				|| end != msg.length() - 1)
			throw new IllegalArgumentException();

		String base64 = msg.substring(MessageConstants.ENCODED_MESSAGE_HEAD.length(),
				end);
		byte[] decodedMessage = Base64.decode(base64.getBytes());
		return decodedMessage;
	}

	public static String encodeMessage(byte[] msgBytes) {
		if (msgBytes == null || msgBytes.length < 1)
			return "";

		byte[] encodedMessage = Base64.encode(msgBytes);
		return MessageConstants.ENCODED_MESSAGE_HEAD + new String(encodedMessage) + ".";
	}
}
