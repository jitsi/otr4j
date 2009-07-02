package net.java.otr4j.message.encoded;

import java.io.*;
import javax.crypto.interfaces.*;

public class MysteriousT {
	public int senderKeyID;
	public int recipientKeyID;
	public DHPublicKey nextDHPublicKey;
	public byte[] ctr;
	public byte[] encryptedMsg;

	public MysteriousT() {

	}

	public MysteriousT(int senderKeyID, int receipientKeyID,
			DHPublicKey nextDHPublicKey, byte[] ctr, byte[] encryptedMsg) {
		this.senderKeyID = senderKeyID;
		this.recipientKeyID = receipientKeyID;
		this.nextDHPublicKey = nextDHPublicKey;
		this.ctr = ctr;
		this.encryptedMsg = encryptedMsg;
	}

	public void readObject(ByteArrayInputStream in) throws IOException {
		senderKeyID = DeserializationUtils.readInt(in);
		recipientKeyID = DeserializationUtils.readInt(in);
		nextDHPublicKey = DeserializationUtils.readDHPublicKey(in);
		ctr = DeserializationUtils.readCtr(in);
		encryptedMsg = DeserializationUtils.readData(in);
	}

	public void writeObject(ByteArrayOutputStream out) throws IOException {
		SerializationUtils.writeInt(out, senderKeyID);
		SerializationUtils.writeInt(out, recipientKeyID);
		SerializationUtils.writeDHPublicKey(out, nextDHPublicKey);
		SerializationUtils.writeCtr(out, ctr);
		SerializationUtils.writeData(out, encryptedMsg);
	}
}
