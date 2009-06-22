package net.java.otr4j.message.encoded.signature;

import net.java.otr4j.message.encoded.EncodedMessageBase;

public abstract class SignatureMessageBase extends EncodedMessageBase {

	public byte[] xEncrypted;
	public byte[] xEncryptedMAC;
}
