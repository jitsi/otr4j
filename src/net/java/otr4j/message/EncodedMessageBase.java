/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.message;

import java.io.*;

/**
 * 
 * @author George Politis
 */
public abstract class EncodedMessageBase extends MessageBase {
	private int protocolVersion;

	public EncodedMessageBase(int messageType) {
		super(messageType);
	}

	public abstract void writeObject(OutputStream out) throws IOException;

	public abstract void readObject(InputStream in) throws IOException;

	public void readObject(String msg) throws IOException {
		ByteArrayInputStream in = null;
		try {
			in = new ByteArrayInputStream(MessageUtils.decodeMessage(msg));
			this.readObject(in);
		} finally {
			if (in != null)
				in.close();
		}
	}

	public String writeObject() throws IOException {
		ByteArrayOutputStream out = null;
		byte[] bosArray = null;
		try {
			out = new ByteArrayOutputStream();
			this.writeObject(out);
			bosArray = out.toByteArray();
		} finally {
			if (out != null)
				out.close();
		}

		String encodedMessage = MessageUtils.encodeMessage(bosArray);
		return encodedMessage;
	}

	public void setProtocolVersion(int protocolVersion) {
		this.protocolVersion = protocolVersion;
	}

	public int getProtocolVersion() {
		return protocolVersion;
	}
}
