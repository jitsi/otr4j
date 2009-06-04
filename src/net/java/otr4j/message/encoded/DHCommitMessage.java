package net.java.otr4j.message.encoded;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.message.MessageCreateException;
import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

/**
 * <pre>
 * D-H Commit Message
 * 
 * This is the first message of the AKE. Bob sends it to Alice to commit to a choice of D-H encryption key (but the key itself is not yet revealed). This allows the secure session id to be much shorter than in OTR version 1, while still preventing a man-in-the-middle attack on it.
 * 
 * Protocol version (SHORT)
 *     The version number of this protocol is 0x0002.
 * Message type (BYTE)
 *     The D-H Commit Message has type 0x02.
 * Encrypted gx (DATA)
 *     Produce this field as follows:
 * 
 * Choose a random value r (128 bits)
 * Choose a random value x (at least 320 bits)
 * Serialize gx as an MPI, gxmpi. [gxmpi will probably be 196 bytes long, starting with &quot;\x00\x00\x00\xc0&quot;.]
 * Encrypt gxmpi using AES128-CTR (http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation), with key r and initial counter value 0. The result will be the same length as gxmpi.
 * Encode this encrypted value as the DATA field.
 * 
 * Hashed gx (DATA)
 *     This is the SHA256 hash of gxmpi.
 * </pre>
 * 
 * @author george
 * 
 */
public final class DHCommitMessage extends EncodedMessageBase {

	private DHCommitMessage() {
		super(MessageType.DH_COMMIT);
	}

	private byte[] gxEncrypted;
	private byte[] gxHash;

	private void setGxEncrypted(byte[] gxEncrypted) {
		this.gxEncrypted = gxEncrypted;
	}

	public byte[] getGxEncrypted() {
		return gxEncrypted;
	}

	private void setGxHash(byte[] gxHash) {
		this.gxHash = gxHash;
	}

	public byte[] getGxHash() {
		return gxHash;
	}

	public static String assemble(DHCommitMessage msg) {
		if (msg == null)
			return "";
		int len = 0;

		// Protocol version (SHORT)
		byte[] protocolVersion = Utils.serializeShort(msg.getProtocolVersion());
		len += protocolVersion.length;

		// Message type (BYTE)
		byte[] messageType = Utils.serializeByte(msg.getMessageType());
		len += messageType.length;

		// Encrypted gx (DATA)
		byte[] serializedGxEncrypted = Utils
				.serializeData(msg.getGxEncrypted());
		len += serializedGxEncrypted.length;

		// Hashed gx (DATA)
		byte[] serializedGxHash = Utils.serializeData(msg.getGxHash());
		len += serializedGxHash.length;

		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(serializedGxEncrypted);
		buff.put(serializedGxHash);

		String encodedMessage = Utils.encodeMessage(buff.array());
		return encodedMessage;
	}

	public static DHCommitMessage disassemble(String msgText) {
		if (msgText == null || !msgText.startsWith(MessageHeader.DH_COMMIT))
			return null;

		byte[] decodedMessage = Utils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = Utils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = Utils.deserializeByte(buff);
		if (msgType != MessageType.DH_COMMIT)
			return null;

		// Encrypted gx (DATA)
		byte[] gx = Utils.deserializeData(buff);

		// Hashed gx (DATA)
		byte[] gxHash = Utils.deserializeData(buff);

		DHCommitMessage msg = new DHCommitMessage();
		msg.setProtocolVersion(protocolVersion);
		msg.setGxEncrypted(gx);
		msg.setGxHash(gxHash);
		return msg;
	}

	/**
	 * 
	 * @param protocolVersion
	 * @param r
	 *            the AES key with which gx will be encrypted.
	 * @param x
	 *            the D-H secret key.
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static DHCommitMessage create(int protocolVersion, byte[] r,
			DHPublicKey gxKey) throws MessageCreateException {
		
		// Get gx.
		byte[] gx = ((DHPublicKey) gxKey).getY().toByteArray();

		// Encrypt gx.
		byte[] gxEncrypted;
		try {
			gxEncrypted = Utils.aesEncrypt(r, gx);
		} catch (Exception e) {
			throw new MessageCreateException(e);
		}

		// Create SHA hash.
		byte[] gxHash;
		try {
			gxHash = Utils.sha256Hash(gx);
		} catch (NoSuchAlgorithmException e) {
			throw new MessageCreateException(e);
		}

		DHCommitMessage msg = new DHCommitMessage();
		msg.setProtocolVersion(protocolVersion);
		msg.setGxEncrypted(gxEncrypted);
		msg.setGxHash(gxHash);
		return msg;
	}
}
