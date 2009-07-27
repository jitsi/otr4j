/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.interfaces.DHPublicKey;


/**
 * 
 * @author George Politis
 */
public class MysteriousT extends EncodedMessageBase {

	private int flags;
	public int senderKeyID;
	public int recipientKeyID;
	public DHPublicKey nextDHPublicKey;
	public byte[] ctr;
	public byte[] encryptedMsg;

	public MysteriousT() {
		super(MessageConstants.DATA);
	}

	public void setFlags(int flags) {
		this.flags = flags;
	}

	public int getFlags() {
		return flags;
	}

	public MysteriousT(int senderKeyID, int receipientKeyID,
			DHPublicKey nextDHPublicKey, byte[] ctr, byte[] encryptedMsg,
			int protocolVersion, int flags) {

		super(MessageConstants.DATA);
		this.setProtocolVersion(protocolVersion);
		this.setFlags(flags);
		this.senderKeyID = senderKeyID;
		this.recipientKeyID = receipientKeyID;
		this.nextDHPublicKey = nextDHPublicKey;
		this.ctr = ctr;
		this.encryptedMsg = encryptedMsg;
	}

	public void readObject(InputStream in) throws IOException {
		this.setProtocolVersion(SerializationUtils.readShort(in));
		this.setMessageType(SerializationUtils.readByte(in));
		this.setFlags(SerializationUtils.readByte(in));

		senderKeyID = SerializationUtils.readInt(in);
		recipientKeyID = SerializationUtils.readInt(in);
		nextDHPublicKey = SerializationUtils.readDHPublicKey(in);
		ctr = SerializationUtils.readCtr(in);
		encryptedMsg = SerializationUtils.readData(in);
	}

	public void writeObject(OutputStream out) throws IOException {
		SerializationUtils.writeShort(out, this.getProtocolVersion());
		SerializationUtils.writeByte(out, this.getMessageType());
		SerializationUtils.writeByte(out, this.getFlags());

		SerializationUtils.writeInt(out, senderKeyID);
		SerializationUtils.writeInt(out, recipientKeyID);
		SerializationUtils.writeDHPublicKey(out, nextDHPublicKey);
		SerializationUtils.writeCtr(out, ctr);
		SerializationUtils.writeData(out, encryptedMsg);
	}

	public byte[] toByteArray() throws IOException {
		ByteArrayOutputStream out = null;
		byte[] bosArray = null;
		try {
			out = new ByteArrayOutputStream();
			this.writeObject(out);
			bosArray = out.toByteArray();
		} finally {
			if (out != null)
				out.close();
		}

		return bosArray;
	}
}
