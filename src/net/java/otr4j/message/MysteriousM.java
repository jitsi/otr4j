/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

import java.io.*;
import java.security.*;
import javax.crypto.interfaces.*;

/**
 * 
 * @author George Politis
 */
public class MysteriousM {

	public MysteriousM(DHPublicKey ourDHPublicKey,
			DHPublicKey theirDHPublicKey, PublicKey ourLongTermPublicKey,
			int ourDHPrivateKeyID) {

		this.setOurDHPublicKey(ourDHPublicKey);
		this.setTheirDHPublicKey(theirDHPublicKey);
		this.setOurLongTermPublicKey(ourLongTermPublicKey);
		this.setOurDHPrivatecKeyID(ourDHPrivateKeyID);
	}

	private DHPublicKey ourDHPublicKey;
	private DHPublicKey theirDHPublicKey;
	private PublicKey ourLongTermPublicKey;
	private int ourDHPrivatecKeyID;

	public void writeObject(OutputStream out) throws IOException {
		SerializationUtils.writeMpi(out, this.getOurDHPublicKey().getY());
		SerializationUtils.writeMpi(out, this.getTheirDHPublicKey().getY());
		try {
			SerializationUtils.writePublicKey(out, this
					.getOurLongTermPublicKey());
		} catch (InvalidKeyException e) {
			throw new IOException(e);
		}
		SerializationUtils.writeInt(out, this.getOurDHPrivatecKeyID());
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
