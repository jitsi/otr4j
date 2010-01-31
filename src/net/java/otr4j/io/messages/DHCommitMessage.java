/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io.messages;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;



/**
 * 
 * @author George Politis
 */
public final class DHCommitMessage extends EncodedMessageBase {

	private byte[] dhPublicKeyEncrypted;
	private byte[] dhPublicKeyHash;

	public DHCommitMessage() {
		super(MessageConstants.DH_COMMIT);
	}

	public void writeObject(OutputStream out) throws IOException {

		SerializationUtils.writeShort(out, this.getProtocolVersion());
		SerializationUtils.writeByte(out, this.getMessageType());
		SerializationUtils.writeData(out, this.getDhPublicKeyEncrypted());
		SerializationUtils.writeData(out, this.getDhPublicKeyHash());
	}

	public void readObject(InputStream in) throws IOException {
		this.setProtocolVersion(SerializationUtils.readShort(in));
		this.setMessageType(SerializationUtils.readByte(in));
		this.setDhPublicKeyEncrypted(SerializationUtils.readData(in));
		this.setDhPublicKeyHash(SerializationUtils.readData(in));
	}

	public DHCommitMessage(int protocolVersion, byte[] gxHash,
			byte[] gxEncrypted) {
		super(MessageConstants.DH_COMMIT);
		this.setMessageType(MessageConstants.DH_COMMIT);
		this.setProtocolVersion(protocolVersion);
		this.setDhPublicKeyEncrypted(gxEncrypted);
		this.setDhPublicKeyHash(gxHash);
	}

	public void setDhPublicKeyHash(byte[] dhPublicKeyHash) {
		this.dhPublicKeyHash = dhPublicKeyHash;
	}

	public byte[] getDhPublicKeyHash() {
		return dhPublicKeyHash;
	}

	public void setDhPublicKeyEncrypted(byte[] dhPublicKeyEncrypted) {
		this.dhPublicKeyEncrypted = dhPublicKeyEncrypted;
	}

	public byte[] getDhPublicKeyEncrypted() {
		return dhPublicKeyEncrypted;
	}
}
