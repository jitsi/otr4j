package net.java.otr4j.io;

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;

import javax.crypto.interfaces.DHPublicKey;

import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.AbstractEncodedMessage;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.AbstractMessage;
import net.java.otr4j.io.messages.SignatureM;
import net.java.otr4j.io.messages.MysteriousT;
import net.java.otr4j.io.messages.SignatureX;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureMessage;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;

public class OtrOutputStream extends FilterOutputStream implements
		SerializationConstants {

	public OtrOutputStream(OutputStream out) {
		super(out);
	}

	private void writeNumber(int value, int length) throws IOException {
		byte[] b = new byte[length];
		for (int i = 0; i < length; i++) {
			int offset = (b.length - 1 - i) * 8;
			b[i] = (byte) ((value >>> offset) & 0xFF);
		}
		write(b);
	}

	public void writeBigInt(BigInteger bi) throws IOException {
		byte[] b = BigIntegers.asUnsignedByteArray(bi);
		writeData(b);
	}

	public void writeByte(int b) throws IOException {
		writeNumber(b, TYPE_LEN_BYTE);
	}

	public void writeData(byte[] b) throws IOException {
		int len = (b == null || b.length < 0) ? 0 : b.length;
		writeNumber(len, DATA_LEN);
		if (len > 0)
			write(b);
	}

	public void writeInt(int i) throws IOException {
		writeNumber(i, TYPE_LEN_INT);

	}

	public void writeShort(int s) throws IOException {
		writeNumber(s, TYPE_LEN_SHORT);

	}

	public void writeMac(byte[] mac) throws IOException {
		if (mac == null || mac.length != TYPE_LEN_MAC)
			throw new IllegalArgumentException();

		write(mac);
	}

	public void writeCtr(byte[] ctr) throws IOException {
		if (ctr == null || ctr.length < 1)
			return;

		int i = 0;
		while (i < TYPE_LEN_CTR && i < ctr.length) {
			write(ctr[i]);
			i++;
		}
	}

	public void writeDHPublicKey(DHPublicKey dhPublicKey) throws IOException {
		byte[] b = BigIntegers.asUnsignedByteArray(dhPublicKey.getY());
		writeData(b);
	}

	public void writePublicKey(PublicKey pubKey) throws IOException {
		if (!(pubKey instanceof DSAPublicKey))
			throw new UnsupportedOperationException(
					"Key types other than DSA are not supported at the moment.");

		DSAPublicKey dsaKey = (DSAPublicKey) pubKey;

		writeShort(0);

		DSAParams dsaParams = dsaKey.getParams();
		writeBigInt(dsaParams.getP());
		writeBigInt(dsaParams.getQ());
		writeBigInt(dsaParams.getG());
		writeBigInt(dsaKey.getY());

	}

	public void writeTlvData(byte[] b) throws IOException {
		int len = (b == null || b.length < 0) ? 0 : b.length;
		writeNumber(len, TLV_LEN);
		if (len > 0)
			write(b);
	}

	public void writeSignature(byte[] signature, PublicKey pubKey)
			throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();
		out.write(signature);
	}

	public void writeMysteriousX(SignatureX x) throws IOException {
		writePublicKey(x.longTermPublicKey);
		writeInt(x.dhKeyID);
		writeSignature(x.signature, x.longTermPublicKey);
	}

	public void writeMessage(AbstractMessage m) throws IOException {
		out.write(SerializationConstants.HEAD);

		boolean isEncoded = false;
		switch (m.messageType) {
		case AbstractMessage.MESSAGE_ERROR:
			ErrorMessage error = (ErrorMessage) m;
			out.write(SerializationConstants.HEAD_ERROR);
			out.write(error.error.getBytes());
			break;
		case AbstractMessage.MESSAGE_PLAINTEXT:
			PlainTextMessage plaintxt = (PlainTextMessage) m;
			out.write(plaintxt.cleanText.getBytes());
			if (plaintxt.versions != null && plaintxt.versions.size() > 0) {
				out.write(" \\t  \\t\\t\\t\\t \\t \\t \\t  ".getBytes());
				for (int version : plaintxt.versions) {
					if (version == 1)
						out.write("  \\t\\t  \\t ".getBytes());

					if (version == 2)
						out.write(" \\t \\t  \\t ".getBytes());
				}
			}
			break;
		case AbstractMessage.MESSAGE_QUERY:
			QueryMessage query = (QueryMessage) m;
			if (query.versions.size() == 1 && query.versions.get(0) == 1) {
				out.write(SerializationConstants.HEAD_QUERY_Q);
			} else {
				out.write(SerializationConstants.HEAD_QUERY_V);
				for (int version : query.versions)
					out.write(String.valueOf(version).getBytes());

				out.write("?".getBytes());
			}
			break;
		case AbstractEncodedMessage.MESSAGE_DHKEY:
		case AbstractEncodedMessage.MESSAGE_REVEALSIG:
		case AbstractEncodedMessage.MESSAGE_SIGNATURE:
		case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
		case AbstractEncodedMessage.MESSAGE_DATA:
			isEncoded = true;
			break;
		default:
			throw new IOException("Illegal message type.");
		}

		if (isEncoded) {
			out.write(SerializationConstants.HEAD_ENCODED);

			// Base64EncoderStream base64 = new Base64EncoderStream(out);
			ByteArrayOutputStream o = new ByteArrayOutputStream();
			OtrOutputStream s = new OtrOutputStream(o);

			switch (m.messageType) {
			case AbstractEncodedMessage.MESSAGE_DHKEY:
				DHKeyMessage dhkey = (DHKeyMessage) m;
				s.writeShort(dhkey.protocolVersion);
				s.writeByte(dhkey.messageType);
				s.writeDHPublicKey(dhkey.dhPublicKey);
				break;
			case AbstractEncodedMessage.MESSAGE_REVEALSIG:
				RevealSignatureMessage revealsig = (RevealSignatureMessage) m;
				s.writeShort(revealsig.protocolVersion);
				s.writeByte(revealsig.messageType);
				s.writeData(revealsig.revealedKey);
				s.writeData(revealsig.xEncrypted);
				s.writeMac(revealsig.xEncryptedMAC);
				break;
			case AbstractEncodedMessage.MESSAGE_SIGNATURE:
				SignatureMessage sig = (SignatureMessage) m;
				s.writeShort(sig.protocolVersion);
				s.writeByte(sig.messageType);
				s.writeData(sig.xEncrypted);
				s.writeMac(sig.xEncryptedMAC);
				break;
			case AbstractEncodedMessage.MESSAGE_DH_COMMIT:
				DHCommitMessage dhcommit = (DHCommitMessage) m;
				s.writeShort(dhcommit.protocolVersion);
				s.writeByte(dhcommit.messageType);
				s.writeData(dhcommit.dhPublicKeyEncrypted);
				s.writeData(dhcommit.dhPublicKeyHash);
				break;
			case AbstractEncodedMessage.MESSAGE_DATA:
				DataMessage data = (DataMessage) m;
				s.writeShort(data.protocolVersion);
				s.writeByte(data.messageType);
				s.writeByte(data.flags);
				s.writeInt(data.senderKeyID);
				s.writeInt(data.recipientKeyID);
				s.writeDHPublicKey(data.nextDH);
				s.writeCtr(data.ctr);
				s.writeData(data.encryptedMessage);
				s.writeMac(data.mac);
				s.writeData(data.oldMACKeys);
				break;
			}

			// base64.flushBase64();
			// TODO: Use a Base64DecoderStream.
			write(Base64.encode(o.toByteArray()));
		}
	}

	public void writeMysteriousX(SignatureM m) throws IOException {
		writeBigInt(m.localPubKey.getY());
		writeBigInt(m.remotePubKey.getY());
		writePublicKey(m.localLongTermPubKey);
		writeInt(m.keyPairID);
	}

	public void writeMysteriousT(MysteriousT t) throws IOException {
		writeShort(t.protocolVersion);
		writeByte(t.messageType);
		writeByte(t.flags);

		writeInt(t.senderKeyID);
		writeInt(t.recipientKeyID);
		writeDHPublicKey(t.nextDH);
		writeCtr(t.ctr);
		writeData(t.encryptedMessage);

	}
}
