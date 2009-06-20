package net.java.otr4j;

import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.PublicKey;
import javax.crypto.interfaces.DHPublicKey;

public class MysteriousM implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
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
	
	private void writeObject(ObjectOutputStream out) {
		
	}
	private void readObject(ObjectOutputStream in) {
	}
}
