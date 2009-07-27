/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.interfaces.DHPublicKey;


/**
 * 
 * @author George Politis
 */
public final class DHKeyMessage extends EncodedMessageBase {

	private DHPublicKey dhPublicKey;

	public DHKeyMessage() {
		super(MessageConstants.DH_KEY);
	}

	public DHKeyMessage(int protocolVersion, DHPublicKey dhPublicKey) {
		super(MessageConstants.DH_KEY);
		this.setDhPublicKey(dhPublicKey);
		this.setProtocolVersion(protocolVersion);
	}

	public void writeObject(OutputStream out) throws IOException {
		SerializationUtils.writeShort(out, this.getProtocolVersion());
		SerializationUtils.writeByte(out, this.getMessageType());
		SerializationUtils.writeDHPublicKey(out, this.getDhPublicKey());
	}

	public void readObject(InputStream in) throws IOException {
		this.setProtocolVersion(SerializationUtils.readShort(in));
		this.setMessageType(SerializationUtils.readByte(in));
		this.setDhPublicKey(SerializationUtils.readDHPublicKey(in));
	}

	public void setDhPublicKey(DHPublicKey dhPublicKey) {
		this.dhPublicKey = dhPublicKey;
	}

	public DHPublicKey getDhPublicKey() {
		return dhPublicKey;
	}
}
