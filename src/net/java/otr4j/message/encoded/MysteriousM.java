package net.java.otr4j.message.encoded;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import javax.crypto.interfaces.DHPublicKey;

public class MysteriousM {

	public MysteriousM(byte[] m1, DHPublicKey ourDHPublicKey,
			DHPublicKey theirDHPublicKey, PublicKey ourLongTermPublicKey,
			int ourDHPrivateKeyID) {

		this.m1 = m1;
		this.ourDHPublicKey = ourDHPublicKey;
		this.theirDHPublicKey = theirDHPublicKey;
		this.ourLongTermPublicKey = ourLongTermPublicKey;
		this.ourDHPrivatecKeyID = ourDHPrivateKeyID;
	}

	public byte[] m1;
	public DHPublicKey ourDHPublicKey;
	public DHPublicKey theirDHPublicKey;
	public PublicKey ourLongTermPublicKey;
	public int ourDHPrivatecKeyID;

	public byte[] compute() throws InvalidKeyException, IOException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		SerializationUtils.writeMpi(bos, this.ourDHPublicKey.getY());
		SerializationUtils.writeMpi(bos, this.theirDHPublicKey.getY());
		SerializationUtils.writePublicKey(bos, this.ourLongTermPublicKey);
		SerializationUtils.writeInt(bos, this.ourDHPrivatecKeyID);

		return bos.toByteArray();
	}
}
