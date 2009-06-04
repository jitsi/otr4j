package net.java.otr4j.message.encoded;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

/**
 * <pre>
 * Signature Message
 * 
 * This is the final message of the AKE. Alice sends it to Bob, authenticating herself and the channel parameters to him.
 * 
 * Protocol version (SHORT)
 *     The version number of this protocol is 0x0002.
 * Message type (BYTE)
 *     The Signature Message has type 0x12.
 * Encrypted signature (DATA)
 *     This field is calculated as follows:
 * 
 * Compute the Diffie-Hellman shared secret s.
 * Use s to compute an AES key c' and two MAC keys m1' and m2', as specified below.
 * Select keyidA, a serial number for the D-H key computed earlier. It is an INT, and must be greater than 0.
 * Compute the 32-byte value MA to be the SHA256-HMAC of the following data, using the key m1':
 * 
 *           gy (MPI)
 *           gx (MPI)
 *           pubA (PUBKEY)
 *           keyidA (INT)
 * 
 * Let XA be the following structure:
 * 
 *           pubA (PUBKEY)
 *           keyidA (INT)
 *           sigA(MA) (SIG)
 *               This is the signature, using the private part of the key pubA, of the 32-byte MA (which does not need to be hashed again to produce the signature).
 * 
 * Encrypt XA using AES128-CTR with key c' and initial counter value 0.
 * Encode this encrypted value as the DATA field.
 * 
 * MAC'd signature (MAC)
 *     This is the SHA256-HMAC-160 (that is, the first 160 bits of the SHA256-HMAC) of the encrypted signature field (including the four-byte length), using the key m2'.
 * </pre>
 * 
 * @author george
 * 
 */
public final class SignatureMessage extends SignatureMessageBase {

	public static SignatureMessage create(int protocolVersion,
			DHPublicKey pubKeyX, DHPublicKey pubKeyY, int keyidB,
			PrivateKey privKey, PublicKey pubKey, byte[] cp, byte[] m1p,
			byte[] m2p) throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchPaddingException, InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {

		byte[] MB = computeMB(pubKeyX, pubKeyY, keyidB, pubKey, m1p);
		byte[] XB = computeXB(privKey, pubKey, keyidB, MB);
		byte[] XBEncrypted = Utils.aesEncrypt(cp, XB);

		byte[] mac = Utils.sha256Hmac160(XBEncrypted, m2p);

		SignatureMessage msg = new SignatureMessage();
		msg.setProtocolVersion(protocolVersion);
		msg.setSignatureMac(mac);
		msg.setEncryptedSignature(XBEncrypted);

		return msg;
	}

	private SignatureMessage() {
		super(MessageType.SIGNATURE);
	}

	public static String assemble(SignatureMessage msg) {
		if (msg == null)
			return "";
		int len = 0;

		// Protocol version (SHORT)
		byte[] protocolVersion = Utils.serializeShort(msg.getProtocolVersion());
		len += protocolVersion.length;

		// Message type (BYTE)
		byte[] messageType = Utils.serializeByte(msg.getMessageType());
		len += messageType.length;

		// Encrypted signature (DATA)
		byte[] serializedEncryptedSignature = Utils.serializeData(msg
				.getEncryptedSignature());
		len += serializedEncryptedSignature.length;

		// MAC'd signature (MAC)
		byte[] serializedSignatureMac = msg.getSignatureMac();
		len += DataLength.MAC;

		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(serializedEncryptedSignature);
		buff.put(serializedSignatureMac);

		String encodedMessage = Utils.encodeMessage(buff.array());
		return encodedMessage;
	}

	public static SignatureMessage disassemble(String msgText) {
		if (!msgText.startsWith(MessageHeader.SIGNATURE))
			return null;

		byte[] decodedMessage = Utils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = Utils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = Utils.deserializeByte(buff);
		if (msgType != MessageType.SIGNATURE)
			return null;

		// Encrypted Signature (DATA)
		byte[] sig = Utils.deserializeData(buff);

		// MAC'd signature (MAC)
		byte[] mac = Utils.deserializeMac(buff);

		SignatureMessage msg = new SignatureMessage();
		msg.setProtocolVersion(protocolVersion);
		msg.setEncryptedSignature(sig);
		msg.setSignatureMac(mac);
		return msg;
	}
}
