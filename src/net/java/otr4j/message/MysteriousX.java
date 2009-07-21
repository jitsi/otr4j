
/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

import java.io.*;
import java.security.*;

/**
 * 
 * @author George Politis
 */
public class MysteriousX {

	public MysteriousX() {

	}

	public MysteriousX(PublicKey ourLongTermPublicKey, int ourKeyID,
			byte[] signature) {
		this.setDhKeyID(ourKeyID);
		this.setLongTermPublicKey(ourLongTermPublicKey);
		this.setSignature(signature);
	}

	public void readObject(byte[] b) throws IOException {
		ByteArrayInputStream bis = null;
		try {
			bis = new ByteArrayInputStream(b);
			this.readObject(bis);
		} catch (Exception e) {
			bis.close();
		}
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException {
		try {
			this.setLongTermPublicKey(SerializationUtils
					.readPublicKey(stream));
		} catch (Exception e) {
			throw new IOException(e);
		}
		this.setDhKeyID(SerializationUtils.readInt(stream));
		this.setSignature(SerializationUtils.readSignature(stream, this
				.getLongTermPublicKey()));
	}

	private PublicKey longTermPublicKey;
	private int dhKeyID;
	private byte[] signature;

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException {

		try {
			SerializationUtils.writePublicKey(stream, this
					.getLongTermPublicKey());
		} catch (Exception e) {
			throw new IOException(e);
		}
		SerializationUtils.writeInt(stream, this.getDhKeyID());
		SerializationUtils.writeSignature(stream, this.getSignature(), this
				.getLongTermPublicKey());
	}

	public byte[] toByteArray() throws IOException{
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
	
	public void setLongTermPublicKey(PublicKey longTermPublicKey) {
		this.longTermPublicKey = longTermPublicKey;
	}

	public PublicKey getLongTermPublicKey() {
		return longTermPublicKey;
	}

	public void setDhKeyID(int dhKeyID) {
		this.dhKeyID = dhKeyID;
	}

	public int getDhKeyID() {
		return dhKeyID;
	}

	public void setSignature(byte[] signature) {
		this.signature = signature;
	}

	public byte[] getSignature() {
		return signature;
	}
}
