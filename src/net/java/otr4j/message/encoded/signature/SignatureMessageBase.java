package net.java.otr4j.message.encoded.signature;

import net.java.otr4j.message.encoded.EncodedMessageBase;

public abstract class SignatureMessageBase extends EncodedMessageBase {

	public byte[] encryptedSignature;
	public byte[] signatureMac;

	public SignatureMessageBase(int messageType) {
		super(messageType);
	}
}
