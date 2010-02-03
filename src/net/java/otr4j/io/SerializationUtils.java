/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package net.java.otr4j.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;

import net.java.otr4j.io.messages.MessageBase;
import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.SignatureX;

/**
 * 
 * @author George Politis
 */
public class SerializationUtils {
	// Mysterious X IO.
	public static SignatureX toMysteriousX(byte[] b) throws IOException {
		ByteArrayInputStream in = new ByteArrayInputStream(b);
		OtrInputStream ois = new OtrInputStream(in);
		SignatureX x = ois.readMysteriousX();
		ois.close();
		return x;
	}

	public static byte[] toByteArray(SignatureX x) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OtrOutputStream oos = new OtrOutputStream(out);
		oos.writeMysteriousX(x);
		byte[] b = out.toByteArray();
		oos.close();
		return b;
	}

	// Mysterious M IO.
	public static byte[] toByteArray(SignatureM m) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OtrOutputStream oos = new OtrOutputStream(out);
		oos.writeMysteriousX(m);
		byte[] b = out.toByteArray();
		oos.close();
		return b;
	}

	// Mysterious T IO.
	public static byte[] toByteArray(MysteriousT t) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OtrOutputStream oos = new OtrOutputStream(out);
		oos.writeMysteriousT(t);
		byte[] b = out.toByteArray();
		out.close();
		return b;
	}

	// Basic IO.
	public static byte[] writeData(byte[] b) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OtrOutputStream oos = new OtrOutputStream(out);
		oos.writeData(b);
		byte[] otrb = out.toByteArray();
		out.close();
		return otrb;
	}

	// BigInteger IO.
	public static byte[] writeMpi(BigInteger bigInt) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OtrOutputStream oos = new OtrOutputStream(out);
		oos.writeBigInt(bigInt);
		byte[] b = out.toByteArray();
		oos.close();
		return b;
	}

	public static BigInteger readMpi(byte[] b) throws IOException {
		ByteArrayInputStream in = new ByteArrayInputStream(b);
		OtrInputStream ois = new OtrInputStream(in);
		BigInteger bigint = ois.readBigInt();
		ois.close();
		return bigint;
	}

	// Public Key IO.
	public static byte[] writePublicKey(PublicKey pubKey) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OtrOutputStream oos = new OtrOutputStream(out);
		oos.writePublicKey(pubKey);
		byte[] b = out.toByteArray();
		oos.close();
		return b;
	}

	// Message IO.
	public static byte[] toByteArray(MessageBase m) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		OtrOutputStream oos = new OtrOutputStream(out);
		oos.writeMessage(m);
		byte[] b = out.toByteArray();
		oos.close();
		return b;
	}

	public static MessageBase toMessage(byte[] b) throws IOException {
		ByteArrayInputStream in = new ByteArrayInputStream(b);
		OtrInputStream ois = new OtrInputStream(in);
		MessageBase m = ois.readMessage();
		ois.close();
		return m;
	}
}
