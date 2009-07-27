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


/**
 * 
 * @author George Politis
 */
public class DataMessage extends EncodedMessageBase {

	private byte[] mac;
	private byte[] oldMACKeys;
	private MysteriousT t;

	public DataMessage() {
		super(MessageConstants.DATA);
	}

	public DataMessage(MysteriousT t, byte[] mac, byte[] oldMacKeys) {
		super(MessageConstants.DATA);
		this.setMac(mac);
		this.setT(t);
		this.setOldMACKeys(oldMacKeys);
	}

	public void readObject(InputStream in) throws IOException {
		setT(new MysteriousT());
		getT().readObject(in);
		this.setMac(SerializationUtils.readMac(in));
		this.setOldMACKeys(SerializationUtils.readData(in));
	}

	public void writeObject(OutputStream out) throws IOException {
		getT().writeObject(out);
		SerializationUtils.writeMac(out, this.getMac());
		SerializationUtils.writeData(out, this.getOldMACKeys());
	}

	public void setMac(byte[] mac) {
		this.mac = mac;
	}

	public byte[] getMac() {
		return mac;
	}

	public void setOldMACKeys(byte[] oldMACKeys) {
		this.oldMACKeys = oldMACKeys;
	}

	public byte[] getOldMACKeys() {
		return oldMACKeys;
	}

	public void setT(MysteriousT t) {
		this.t = t;
	}

	public MysteriousT getT() {
		return t;
	}
}
