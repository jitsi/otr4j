package net.java.otr4j.message.encoded;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class MysteriousX {

	public MysteriousX(PublicKey ourLongTermPublicKey, int ourKeyID,
			BigInteger[] signatureRS) {
		this.dhKeyID = ourKeyID;
		this.publicKey = ourLongTermPublicKey;
		this.signatureRS = signatureRS;
	}

	public void readObject(java.io.ByteArrayInputStream stream)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		this.publicKey = DeserializationUtils.readPublicKey(stream);
		this.dhKeyID = DeserializationUtils.readInt(stream);
		this.signatureRS = DeserializationUtils.readSignature(stream);
	}

	public PublicKey publicKey;
	public int dhKeyID;
	public BigInteger[] signatureRS;

	public void writeObject(java.io.ByteArrayOutputStream stream)
			throws IOException, InvalidKeyException {

		SerializationUtils.writePublicKey(stream, this.publicKey);
		SerializationUtils.writeInt(stream, this.dhKeyID);
		SerializationUtils.writeSignature(stream, this.signatureRS);
	}
}
