package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

/**
 * <pre>
 * Data Message
 * 
 * This message is used to transmit a private message to the correspondent. It is also used to reveal old MAC keys.
 * 
 * The plaintext message (either before encryption, or after decryption) consists of a human-readable message (encoded in UTF-8, optionally with HTML markup), optionally followed by:
 * 
 * a single NUL (a BYTE with value 0x00), and
 * zero or more TLV (type/length/value) records (with no padding between them)
 * 
 * Each TLV record is of the form:
 * 
 * Type (SHORT)
 *     The type of this record. Records with unrecognized types should be ignored.
 * Length (SHORT)
 *     The length of the following field
 * Value (len BYTEs) [where len is the value of the Length field]
 *     Any pertinent data for the record type.
 * 
 * Some TLV examples:
 * 
 * \x00\x01\x00\x00
 *     A TLV of type 1, containing no data
 * \x00\x00\x00\x05\x68\x65\x6c\x6c\x6f
 *     A TLV of type 0, containing the value &quot;hello&quot;
 * 
 * The currently defined TLV record types are:
 * 
 * Type 0: Padding
 *     The value may be an arbitrary amount of data, which should be ignored. This type can be used to disguise the length of the plaintext message.
 * Type 1: Disconnected
 *     If the user requests to close the private connection, you may send a message (possibly with empty human-readable part) containing a record with this TLV type just before you discard the session keys, and transition to MSGSTATE_PLAINTEXT (see below). If you receive a TLV record of this type, you should transition to MSGSTATE_FINISHED (see below), and inform the user that his correspondent has closed his end of the private connection, and the user should do the same.
 * Type 2: SMP Message 1
 *     The value represents an initiating message of the Socialist Millionaires' Protocol, described below.
 * Type 3: SMP Message 2
 *     The value represents the second message in an instance of SMP.
 * Type 4: SMP Message 3
 *     The value represents the third message in an instance of SMP.
 * Type 5: SMP Message 4
 *     The value represents the final message in an instance of SMP.
 * Type 6: SMP Abort Message
 *     If the user cancels SMP prematurely or encounters an error in the protocol and cannot continue, you may send a message (possibly with empty human-readable part) with this TLV type to instruct the other party's client to abort the protocol. The associated length should be zero and the associated value should be empty. If you receive a TLV of this type, you should change the SMP state to SMP_EXPECT1 (see below).
 * 
 * SMP Message TLVs (types 2-5) all carry data sharing the same general format:
 * 
 * MPI count (INT)
 *     The number of MPIs contained in the remainder of the TLV.
 * MPI 1 (MPI)
 *     The first MPI of the TLV, serialized into a byte array.
 * MPI 2 (MPI)
 *     The second MPI of the TLV, serialized into a byte array.
 * etc.
 * 
 * There should be as many MPIs as declared in the MPI count field. For the exact MPIs passed for each SMP TLV, see the SMP state machine below.
 * 
 * A message with an empty human-readable part (the plaintext is of zero length, or starts with a NUL) is a &quot;heartbeat&quot; packet, and should not be displayed to the user. (But it's still useful to effect key rotations.)
 * 
 * Data Message format:
 * 
 * Protocol version (SHORT)
 *     The version number of this protocol is 0x0002.
 * Message type (BYTE)
 *     The Data Message has type 0x03.
 * Flags (BYTE)
 *     The bitwise-OR of the flags for this message. Usually you should set this to 0x00. The only currently defined flag is:
 * 
 *     IGNORE_UNREADABLE (0x01)
 *         If you receive a Data Message with this flag set, and you are unable to decrypt the message or verify the MAC (because, for example, you don't have the right keys), just ignore the message instead of producing some kind of error or notification to the user. 
 * 
 * Sender keyid (INT)
 *     Must be strictly greater than 0, and increment by 1 with each key change
 * Recipient keyid (INT)
 *     Must therefore be strictly greater than 0, as the receiver has no key with id 0.
 *     The sender and recipient keyids are those used to encrypt and MAC this message.
 * DH y (MPI)
 *     The *next* [i.e. sender_keyid+1] public key for the sender
 * Top half of counter init (CTR)
 *     This should monotonically increase (as a big-endian value) for each message sent with the same (sender keyid, recipient keyid) pair, and must not be all 0x00.
 * Encrypted message (DATA)
 *     Using the appropriate encryption key (see below) derived from the sender's and recipient's DH public keys (with the keyids given in this message), perform AES128 counter-mode (CTR) encryption of the message. The initial counter is a 16-byte value whose first 8 bytes are the above &quot;top half of counter init&quot; value, and whose last 8 bytes are all 0x00. Note that counter mode does not change the length of the message, so no message padding needs to be done. If you *want* to do message padding (to disguise the length of your message), use the above TLV of type 0.
 * Authenticator (MAC)
 *     The SHA1-HMAC, using the appropriate MAC key (see below) of everything from the Protocol version to the end of the encrypted message
 * Old MAC keys to be revealed (DATA)
 *     See &quot;Revealing MAC Keys&quot;, below.
 * </pre>
 * 
 * @author george
 * 
 */
public class DataMessage extends EncodedMessageBase {

	private DataMessage() {
		super(MessageType.DATA);
	}

	private int flags;
	private int senderKeyID;
	private int recipientKeyID;
	private BigInteger ympi;
	private byte[] ctr;
	private byte[] msg;
	private byte[] mac;
	private byte[] oldKeys;

	public void setFlags(int flags) {
		this.flags = flags;
	}

	public int getFlags() {
		return flags;
	}

	public void setRecipientKeyID(int recipientKeyID) {
		this.recipientKeyID = recipientKeyID;
	}

	public int getRecipientKeyID() {
		return recipientKeyID;
	}

	public void setSenderKeyID(int senderKeyID) {
		this.senderKeyID = senderKeyID;
	}

	public int getSenderKeyID() {
		return senderKeyID;
	}

	public void setYmpi(BigInteger ympi) {
		this.ympi = ympi;
	}

	public BigInteger getYmpi() {
		return ympi;
	}

	public void setCtr(byte[] ctr) {
		this.ctr = ctr;
	}

	public byte[] getCtr() {
		return ctr;
	}

	public void setMsg(byte[] msg) {
		this.msg = msg;
	}

	public byte[] getMsg() {
		return msg;
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

	public byte[] getMac() {
		return mac;
	}

	public void setOldKeys(byte[] oldKeys) {
		this.oldKeys = oldKeys;
	}

	public byte[] getOldKeys() {
		return oldKeys;
	}

	public static DataMessage disassemble(String msgText) {
		if (!msgText.startsWith(MessageHeader.DATA1)
				&& !msgText.startsWith(MessageHeader.DATA2))
			return null;
		byte[] decodedMessage = Utils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);

		// Protocol version (SHORT)
		int protocolVersion = Utils.deserializeShort(buff);

		// Message type (BYTE)
		int msgType = Utils.deserializeByte(buff);
		if (msgType != MessageType.DATA)
			return null;

		// Flags (BYTE)
		int flags = Utils.deserializeByte(buff);
		// Sender keyid (INT)
		int senderKeyID = Utils.deserializeInt(buff);
		// Recipient keyid (INT)
		int receiverKeyID = Utils.deserializeInt(buff);

		// DH y (MPI)
		BigInteger ympi = Utils.deserializeMpi(buff);

		// Top half of counter init (CTR)
		byte[] ctr = Utils.deserializeCtr(buff);

		// Encrypted message (DATA)
		byte[] msg = Utils.deserializeData(buff);

		// Authenticator (MAC)
		byte[] mac = Utils.deserializeMac(buff);

		// Old MAC keys to be revealed (DATA)
		byte[] oldKeys = Utils.deserializeData(buff);

		DataMessage dataMessage = new DataMessage();
		dataMessage.setFlags(flags);
		dataMessage.setSenderKeyID(senderKeyID);
		dataMessage.setRecipientKeyID(receiverKeyID);
		dataMessage.setYmpi(ympi);
		dataMessage.setCtr(ctr);
		dataMessage.setMsg(msg);
		dataMessage.setMac(mac);
		dataMessage.setOldKeys(oldKeys);

		dataMessage.setProtocolVersion(protocolVersion);
		
		return dataMessage;

	}

}
