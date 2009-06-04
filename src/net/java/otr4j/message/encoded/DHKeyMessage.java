package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

/**
 * <pre>
 * D-H Key Message
 * 
 * This is the second message of the AKE. Alice sends it to Bob, and it simply consists of Alice's D-H encryption key.
 * 
 * Protocol version (SHORT)
 *     The version number of this protocol is 0x0002.
 * Message type (BYTE)
 *     The D-H Key Message has type 0x0a.
 * gy (MPI)
 *     Choose a random value y (at least 320 bits), and calculate gy.
 * </pre>
 * 
 * @author george
 * 
 */
public final class DHKeyMessage extends EncodedMessageBase {

	private DHPublicKey gy;

	private DHKeyMessage() {
		super(MessageType.DH_KEY);
	}

	private void setGy(DHPublicKey gy) {
		this.gy = gy;
	}

	public DHPublicKey getGy() {
		return gy;
	}

	public static DHKeyMessage create(int protocolVersion, DHPublicKey gy) {

		DHKeyMessage msg = new DHKeyMessage();

		msg.setGy(gy);
		msg.setProtocolVersion(protocolVersion);

		return msg;
	}

	public static String assemble(DHKeyMessage msg) {
		if (msg == null)
			return "";

		int len = 0;
		// Protocol version (SHORT)
		byte[] protocolVersion = Utils.serializeShort(msg.getProtocolVersion());
		len += protocolVersion.length;

		// Message type (BYTE)
		byte[] messageType = Utils.serializeByte(msg.getProtocolVersion());
		len += messageType.length;

		// gy (MPI)
		byte[] gyMpiSerialized = Utils.serializeDHPublicKey(msg.getGy());
		len += gyMpiSerialized.length;

		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(gyMpiSerialized);

		String encodedMessage = Utils.encodeMessage(buff.array());
		return encodedMessage;
	}

	public static DHKeyMessage disassemble(String msgText)
			throws MessageDisassembleException {
		if (msgText == null || !msgText.startsWith(MessageHeader.DH_KEY))
			return null;

		byte[] decodedMessage = Utils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = Utils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = Utils.deserializeByte(buff);
		if (msgType != MessageType.DH_KEY)
			return null;

		// gy (MPI)
		BigInteger gyMpi = Utils.deserializeMpi(buff);
		DHPublicKey gyKey = null;
		try {
			gyKey = Utils.getDHPublicKey(gyMpi);
		} catch (Exception e) {
			throw new MessageDisassembleException(e);
		}

		DHKeyMessage msg = new DHKeyMessage();
		msg.setProtocolVersion(protocolVersion);
		msg.setGy(gyKey);

		return msg;
	}
}
