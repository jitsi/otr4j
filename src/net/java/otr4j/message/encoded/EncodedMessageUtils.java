package net.java.otr4j.message.encoded;


import net.java.otr4j.message.*;
import org.bouncycastle.util.encoders.*;

public final class EncodedMessageUtils {

	public static byte[] decodeMessage(String msg) {
		int end = msg.lastIndexOf(".");

		if (msg.indexOf(MessageHeader.ENCODED_MESSAGE) != 0
				|| end != msg.length() - 1)
			throw new IllegalArgumentException();

		String base64 = msg.substring(MessageHeader.ENCODED_MESSAGE.length(),
				end);
		byte[] decodedMessage = Base64.decode(base64.getBytes());
		return decodedMessage;
	}

	public static String encodeMessage(byte[] msgBytes) {
		if (msgBytes == null || msgBytes.length < 1)
			return "";

		byte[] encodedMessage = Base64.encode(msgBytes);
		return MessageHeader.ENCODED_MESSAGE + new String(encodedMessage) + ".";
	}
}
