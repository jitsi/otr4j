package net.java.otr4j.message;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;



public final class RevealSignatureMessage extends SignatureMessageBase {

	public RevealSignatureMessage(int protocolVersion, byte[] r,
			byte[] xEncryptedMAC, byte[] xEncrypted) {

		super(MessageConstants.REVEALSIG);
		this.setProtocolVersion(protocolVersion);
		this.setXEncryptedMAC(xEncryptedMAC);
		this.setXEncrypted(xEncrypted);
		this.setRevealedKey(r);
	}

	private byte[] revealedKey;

	public RevealSignatureMessage() {
		super(MessageConstants.REVEALSIG);
	}

	public void writeObject(OutputStream out) throws IOException {

		SerializationUtils.writeShort(out, this.getProtocolVersion());
		SerializationUtils.writeByte(out, this.getMessageType());
		SerializationUtils.writeData(out, this.getRevealedKey());
		SerializationUtils.writeData(out, this.getXEncrypted());
		SerializationUtils.writeMac(out, this.getXEncryptedMAC());
	}

	public void readObject(InputStream in) throws IOException {
		this.setProtocolVersion(SerializationUtils.readShort(in));
		this.setMessageType(SerializationUtils.readByte(in));
		if (getMessageType() != MessageConstants.REVEALSIG)
			throw new IOException("Object is not reveal signature.");

		this.setRevealedKey(SerializationUtils.readData(in));
		this.setXEncrypted(SerializationUtils.readData(in));
		this.setXEncryptedMAC(SerializationUtils.readMac(in));
	}

	public void setRevealedKey(byte[] revealedKey) {
		this.revealedKey = revealedKey;
	}

	public byte[] getRevealedKey() {
		return revealedKey;
	}
}
