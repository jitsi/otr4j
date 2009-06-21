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
		this.dhKeyID = ourKeyID;
		this.publicKey = ourLongTermPublicKey;
		this.signature = signature;
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
		this.publicKey = DeserializationUtils.readPublicKey(stream);
		this.dhKeyID = DeserializationUtils.readInt(stream);
		this.signature = DeserializationUtils.readSignature(stream,
				this.publicKey);
	}

	public PublicKey publicKey;
	public int dhKeyID;
	public byte[] signature;

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException, InvalidKeyException {

		SerializationUtils.writePublicKey(stream, this.publicKey);
		SerializationUtils.writeInt(stream, this.dhKeyID);
		SerializationUtils.writeSignature(stream, this.signature,
				this.publicKey);
	}
}
