package net.java.otr4j.message.encoded;

import java.io.*;
import java.security.*;
import javax.crypto.interfaces.*;

import net.java.otr4j.crypto.CryptoUtils;

public class MysteriousM {

	public MysteriousM(byte[] m1, DHPublicKey ourDHPublicKey,
			DHPublicKey theirDHPublicKey, PublicKey ourLongTermPublicKey,
			int ourDHPrivateKeyID) {

		this.setM1(m1);
		this.setOurDHPublicKey(ourDHPublicKey);
		this.setTheirDHPublicKey(theirDHPublicKey);
		this.setOurLongTermPublicKey(ourLongTermPublicKey);
		this.setOurDHPrivatecKeyID(ourDHPrivateKeyID);
	}

	private byte[] m1;
	private DHPublicKey ourDHPublicKey;
	private DHPublicKey theirDHPublicKey;
	private PublicKey ourLongTermPublicKey;
	private int ourDHPrivatecKeyID;

	public byte[] compute() throws InvalidKeyException, IOException,
			NoSuchAlgorithmException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		SerializationUtils.writeMpi(bos, this.getOurDHPublicKey().getY());
		SerializationUtils.writeMpi(bos, this.getTheirDHPublicKey().getY());
		SerializationUtils.writePublicKey(bos, this.getOurLongTermPublicKey());
		SerializationUtils.writeInt(bos, this.getOurDHPrivatecKeyID());

		byte[] result = bos.toByteArray();
		bos.close();
		return CryptoUtils.sha256Hash(result);
	}

	public void setM1(byte[] m1) {
		this.m1 = m1;
	}

	public byte[] getM1() {
		return m1;
	}

	public void setOurDHPublicKey(DHPublicKey ourDHPublicKey) {
		this.ourDHPublicKey = ourDHPublicKey;
	}

	public DHPublicKey getOurDHPublicKey() {
		return ourDHPublicKey;
	}

	public void setTheirDHPublicKey(DHPublicKey theirDHPublicKey) {
		this.theirDHPublicKey = theirDHPublicKey;
	}

	public DHPublicKey getTheirDHPublicKey() {
		return theirDHPublicKey;
	}

	public void setOurLongTermPublicKey(PublicKey ourLongTermPublicKey) {
		this.ourLongTermPublicKey = ourLongTermPublicKey;
	}

	public PublicKey getOurLongTermPublicKey() {
		return ourLongTermPublicKey;
	}

	public void setOurDHPrivatecKeyID(int ourDHPrivatecKeyID) {
		this.ourDHPrivatecKeyID = ourDHPrivatecKeyID;
	}

	public int getOurDHPrivatecKeyID() {
		return ourDHPrivatecKeyID;
	}
}
