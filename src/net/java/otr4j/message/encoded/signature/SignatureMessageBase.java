package net.java.otr4j.message.encoded.signature;

import net.java.otr4j.message.encoded.EncodedMessageBase;

public abstract class SignatureMessageBase extends EncodedMessageBase {

	private byte[] xEncrypted;
	private byte[] xEncryptedMAC;
	public void setXEncryptedMAC(byte[] xEncryptedMAC) {
		this.xEncryptedMAC = xEncryptedMAC;
	}
	public byte[] getXEncryptedMAC() {
		return xEncryptedMAC;
	}
	public void setXEncrypted(byte[] xEncrypted) {
		this.xEncrypted = xEncrypted;
	}
	public byte[] getXEncrypted() {
		return xEncrypted;
	}
}
