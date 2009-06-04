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
 * Reveal Signature Message
 * 
 * This is the third message of the AKE. Bob sends it to Alice, revealing his D-H encryption key (and thus opening an encrypted channel), and also authenticating himself (and the parameters of the channel, preventing a man-in-the-middle attack on the channel itself) to Alice.
 * 
 * Protocol version (SHORT)
 *     The version number of this protocol is 0x0002.
 * Message type (BYTE)
 *     The Reveal Signature Message has type 0x11.
 * Revealed key (DATA)
 *     This is the value r picked earlier.
 * Encrypted signature (DATA)
 *     This field is calculated as follows:
 * 
 * Compute the Diffie-Hellman shared secret s.
 * Use s to compute an AES key c and two MAC keys m1 and m2, as specified below.
 * Select keyidB, a serial number for the D-H key computed earlier. It is an INT, and must be greater than 0.
 * Compute the 32-byte value MB to be the SHA256-HMAC of the following data, using the key m1:
 * 
 *           gx (MPI)
 *           gy (MPI)
 *           pubB (PUBKEY)
 *           keyidB (INT)
 * 
 * Let XB be the following structure:
 * 
 *           pubB (PUBKEY)
 *           keyidB (INT)
 *           sigB(MB) (SIG)
 *               This is the signature, using the private part of the key pubB, of the 32-byte MB (which does not need to be hashed again to produce the signature).
 * 
 * Encrypt XB using AES128-CTR with key c and initial counter value 0.
 * Encode this encrypted value as the DATA field.
 * 
 * MAC'd signature (MAC)
 *     This is the SHA256-HMAC-160 (that is, the first 160 bits of the SHA256-HMAC) of the encrypted signature field (including the four-byte length), using the key m2.
 * </pre>
 * 
 * @author george
 * 
 */
public final class RevealSignatureMessage extends SignatureMessageBase {

	public static RevealSignatureMessage create(int protocolVersion,
			DHPublicKey gxKey, DHPublicKey gyKey, int keyidB,
			PrivateKey privKey, PublicKey pubKey, byte[] c, byte[] m1,
			byte[] m2, byte[] r) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, SignatureException {

		byte[] MB = computeMB(gxKey, gyKey, keyidB, pubKey, m1);
		byte[] XB = computeXB(privKey, pubKey, keyidB, MB);
		byte[] XBEncrypted = Utils.aesEncrypt(c, XB);

		byte[] mac = Utils.sha256Hmac160(XBEncrypted, m2);

		RevealSignatureMessage msg = new RevealSignatureMessage();
		msg.setProtocolVersion(protocolVersion);
		msg.setSignatureMac(mac);
		msg.setEncryptedSignature(XBEncrypted);
		msg.setRevealedKey(r);

		return msg;
	}

	private RevealSignatureMessage() {
		super(MessageType.REVEALSIG);
	}

	private byte[] revealedKey;

	private void setRevealedKey(byte[] revealedKey) {
		this.revealedKey = revealedKey;
	}

	public byte[] getRevealedKey() {
		return revealedKey;
	}

	public static String assemble(RevealSignatureMessage msg) {
		if (msg == null)
			return "";

		int len = 0;
		// Protocol version (SHORT)
		byte[] protocolVersion = Utils.serializeShort(msg.getProtocolVersion());
		len += protocolVersion.length;

		// Message type (BYTE)
		byte[] messageType = Utils.serializeByte(msg.getMessageType());
		len += messageType.length;

		// Revealed key (DATA)
		byte[] serializedRevealedKey = Utils
				.serializeData(msg.getRevealedKey());
		len += serializedRevealedKey.length;

		// Encrypted Signature (DATA)
		byte[] serializedSig = Utils.serializeData(msg.getEncryptedSignature());
		len += serializedSig.length;

		// MAC'd signature (MAC)
		byte[] mac = msg.getSignatureMac();
		len += DataLength.MAC;

		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(serializedRevealedKey);
		buff.put(serializedSig);
		buff.put(mac);

		String encodedMessage = Utils.encodeMessage(buff.array());
		return encodedMessage;
	}

	public static RevealSignatureMessage disassemble(String msgText) {
		if (msgText == null || !msgText.startsWith(MessageHeader.REVEALSIG))
			return null;

		byte[] decodedMessage = Utils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = Utils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = Utils.deserializeByte(buff);
		if (msgType != MessageType.REVEALSIG)
			return null;

		// Revealed key (DATA)
		byte[] revealedKey = Utils.deserializeData(buff);

		// Encrypted Signature (DATA)
		byte[] sig = Utils.deserializeData(buff);

		// MAC'd signature (MAC)
		byte[] mac = Utils.deserializeMac(buff);

		RevealSignatureMessage msg = new RevealSignatureMessage();
		msg.setProtocolVersion(protocolVersion);
		msg.setRevealedKey(revealedKey);
		msg.setEncryptedSignature(sig);
		msg.setSignatureMac(mac);
		return msg;
	}
}
