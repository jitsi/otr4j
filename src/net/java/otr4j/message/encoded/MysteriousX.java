package net.java.otr4j.message.encoded;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class MysteriousX {

	public MysteriousX() {

	}

	public MysteriousX(PublicKey ourLongTermPublicKey, int ourKeyID,
			byte[] signature) {
		this.setDhKeyID(ourKeyID);
		this.setLongTermPublicKey(ourLongTermPublicKey);
		this.setSignature(signature);
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		this.setLongTermPublicKey(DeserializationUtils.readPublicKey(stream));
		this.setDhKeyID(DeserializationUtils.readInt(stream));
		this.setSignature(DeserializationUtils.readSignature(stream,
				this.getLongTermPublicKey()));
	}

	private PublicKey longTermPublicKey;
	private int dhKeyID;
	private byte[] signature;

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException, InvalidKeyException {

		SerializationUtils.writePublicKey(stream, this.getLongTermPublicKey());
		SerializationUtils.writeInt(stream, this.getDhKeyID());
		SerializationUtils.writeSignature(stream, this.getSignature(),
				this.getLongTermPublicKey());
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
