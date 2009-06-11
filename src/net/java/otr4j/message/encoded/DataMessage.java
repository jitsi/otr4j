package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

public class DataMessage extends EncodedMessageBase {

	private DataMessage() {
		super(MessageType.DATA);
	}

	public int flags;
	public int senderKeyID;
	public int recipientKeyID;
	public BigInteger ympi;
	public byte[] ctr;
	public byte[] msg;
	public byte[] mac;
	public byte[] oldKeys;
	
	public DataMessage(String msgText){
		this();
		if (!msgText.startsWith(MessageHeader.DATA1)
				&& !msgText.startsWith(MessageHeader.DATA2))
			return;
		byte[] decodedMessage = EncodedMessageUtils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);
	
		// Protocol version (SHORT)
		int protocolVersion = EncodedMessageUtils.deserializeShort(buff);
	
		// Message type (BYTE)
		int msgType = EncodedMessageUtils.deserializeByte(buff);
		if (msgType != MessageType.DATA)
			return;
	
		// Flags (BYTE)
		int flags = EncodedMessageUtils.deserializeByte(buff);
		// Sender keyid (INT)
		int senderKeyID = EncodedMessageUtils.deserializeInt(buff);
		// Recipient keyid (INT)
		int receiverKeyID = EncodedMessageUtils.deserializeInt(buff);
	
		// DH y (MPI)
		BigInteger ympi = EncodedMessageUtils.deserializeMpi(buff);
	
		// Top half of counter init (CTR)
		byte[] ctr = EncodedMessageUtils.deserializeCtr(buff);
	
		// Encrypted message (DATA)
		byte[] msg = EncodedMessageUtils.deserializeData(buff);
	
		// Authenticator (MAC)
		byte[] mac = EncodedMessageUtils.deserializeMac(buff);
	
		// Old MAC keys to be revealed (DATA)
		byte[] oldKeys = EncodedMessageUtils.deserializeData(buff);
	
		this.flags = flags;
		this.senderKeyID = senderKeyID;
		this.recipientKeyID = receiverKeyID;
		this.ympi = ympi;
		this.ctr = ctr;
		this.msg = msg;
		this.mac = mac;
		this.oldKeys = oldKeys;
	
		this.protocolVersion = protocolVersion;
		
	}
}
