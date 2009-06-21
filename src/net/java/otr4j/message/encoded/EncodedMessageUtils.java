package net.java.otr4j.message.encoded;


import net.java.otr4j.message.MessageHeader;
import org.apache.commons.codec.binary.Base64;

public final class EncodedMessageUtils {

	public static byte[] decodeMessage(String msg) {
		int end = msg.lastIndexOf(".");

		if (msg.indexOf(MessageHeader.ENCODED_MESSAGE) != 0
				|| end != msg.length() - 1)
			throw new IllegalArgumentException();

		String base64 = msg.substring(MessageHeader.ENCODED_MESSAGE.length(),
				end);
		byte[] decodedMessage = Base64.decodeBase64(base64.getBytes());
		return decodedMessage;
	}

	public static String encodeMessage(byte[] msgBytes) {
		if (msgBytes == null || msgBytes.length < 1)
			return "";

		byte[] encodedMessage = Base64.encodeBase64(msgBytes);
		return MessageHeader.ENCODED_MESSAGE + new String(encodedMessage) + ".";
	}
}
