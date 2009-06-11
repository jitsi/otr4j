package net.java.otr4j.message.encoded;

public abstract class SignatureMessageBase extends EncodedMessageBase {

	public byte[] encryptedSignature;
	public byte[] signatureMac;

	public SignatureMessageBase(int messageType) {
		super(messageType);
	}
}
