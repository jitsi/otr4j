package net.java.otr4j;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import net.java.otr4j.message.encoded.EncodedMessageUtils;

public class MysteriousX implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public MysteriousX(PublicKey ourLongTermPublicKey, int ourKeyID,
			BigInteger[] signatureRS) {
		this.ourKeyID = ourKeyID;
		this.ourLongTermPublicKey = ourLongTermPublicKey;
		this.signatureRS = signatureRS;
	}

	public MysteriousX(byte[] x) {

	}

	public PublicKey ourLongTermPublicKey;
	public int ourKeyID;
	public BigInteger[] signatureRS;

	private void writeObject(ObjectOutputStream out)
	
			throws InvalidKeyException, IOException {
		byte[] pubBBytes = EncodedMessageUtils
				.serializePublicKey(this.ourLongTermPublicKey);
		byte[] keyidBBytes = EncodedMessageUtils.serializeInt(this.ourKeyID);

		int len = pubBBytes.length + keyidBBytes.length;
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(pubBBytes);
		buff.put(keyidBBytes);
		out.write(buff.array());
	}

	private void readObject(ObjectOutputStream in) {
	}
}
