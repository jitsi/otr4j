package net.java.otr4j.message.encoded;

import java.io.*;
import java.security.*;
import javax.crypto.interfaces.*;
import net.java.otr4j.crypto.*;

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

	private byte[] sha256Hmac(byte[] key) throws InvalidKeyException, IOException,
			NoSuchAlgorithmException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		SerializationUtils.writeMpi(bos, this.getOurDHPublicKey().getY());
		SerializationUtils.writeMpi(bos, this.getTheirDHPublicKey().getY());
		SerializationUtils.writePublicKey(bos, this.getOurLongTermPublicKey());
		SerializationUtils.writeInt(bos, this.getOurDHPrivatecKeyID());

		byte[] result = bos.toByteArray();
		bos.close();
		return CryptoUtils.sha256Hmac(result, key);
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

	public Boolean verify(byte[] key, PublicKey pubKey, byte[] signature)
			throws InvalidKeyException, NoSuchAlgorithmException,
			SignatureException, IOException {
		return CryptoUtils.verify(this.sha256Hmac(key), pubKey, signature);
	}

	public byte[] sign(byte[] key, PrivateKey privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, IOException,
			SignatureException {
		byte[] hash = this.sha256Hmac(key);
		return CryptoUtils.sign(hash, privateKey);
	}
}
