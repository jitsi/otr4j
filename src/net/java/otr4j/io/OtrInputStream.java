package net.java.otr4j.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.util.encoders.Base64;

import net.java.otr4j.crypto.OtrCryptoEngineImpl;
import net.java.otr4j.io.messages.DHCommitMessage;
import net.java.otr4j.io.messages.DHKeyMessage;
import net.java.otr4j.io.messages.DataMessage;
import net.java.otr4j.io.messages.EncodedMessageBase;
import net.java.otr4j.io.messages.ErrorMessage;
import net.java.otr4j.io.messages.MessageBase;
import net.java.otr4j.io.messages.SignatureX;
import net.java.otr4j.io.messages.PlainTextMessage;
import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.RevealSignatureMessage;
import net.java.otr4j.io.messages.SignatureMessage;

public class OtrInputStream extends FilterInputStream implements
		net.java.otr4j.io.SerializationConstants {

	public OtrInputStream(InputStream in) {
		super(in);
	}

	private int readNumber(int length) throws IOException {
		byte[] b = new byte[length];
		read(b);

		int value = 0;
		for (int i = 0; i < b.length; i++) {
			int shift = (b.length - 1 - i) * 8;
			value += (b[i] & 0x000000FF) << shift;
		}

		return value;
	}

	public int readByte() throws IOException {
		return readNumber(TYPE_LEN_BYTE);
	}

	public int readInt() throws IOException {
		return readNumber(TYPE_LEN_INT);
	}

	public int readShort() throws IOException {
		return readNumber(TYPE_LEN_SHORT);
	}

	public byte[] readCtr() throws IOException {
		byte[] b = new byte[TYPE_LEN_CTR];
		read(b);
		return b;
	}

	public byte[] readMac() throws IOException {
		byte[] b = new byte[TYPE_LEN_MAC];
		read(b);
		return b;
	}

	public BigInteger readBigInt() throws IOException {
		byte[] b = readData();
		return new BigInteger(1, b);
	}

	public byte[] readData() throws IOException {
		int dataLen = readNumber(DATA_LEN);
		byte[] b = new byte[dataLen];
		read(b);
		return b;
	}

	public PublicKey readPublicKey() throws IOException {
		int type = readShort();
		switch (type) {
		case 0:
			BigInteger p = readBigInt();
			BigInteger q = readBigInt();
			BigInteger g = readBigInt();
			BigInteger y = readBigInt();
			DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
			KeyFactory keyFactory;
			try {
				keyFactory = KeyFactory.getInstance("DSA");
			} catch (NoSuchAlgorithmException e) {
				throw new IOException();
			}
			try {
				return keyFactory.generatePublic(keySpec);
			} catch (InvalidKeySpecException e) {
				throw new IOException();
			}
		default:
			throw new UnsupportedOperationException();
		}
	}

	public DHPublicKey readDHPublicKey() throws IOException {
		BigInteger gyMpi = readBigInt();
		try {
			return new OtrCryptoEngineImpl().getDHPublicKey(gyMpi);
		} catch (Exception ex) {
			throw new IOException();
		}
	}

	public byte[] readTlvData() throws IOException {
		int len = readNumber(TYPE_LEN_BYTE);

		byte[] b = new byte[len];
		in.read(b);
		return b;
	}

	public byte[] readSignature(PublicKey pubKey) throws IOException {
		if (!pubKey.getAlgorithm().equals("DSA"))
			throw new UnsupportedOperationException();

		DSAPublicKey dsaPubKey = (DSAPublicKey) pubKey;
		DSAParams dsaParams = dsaPubKey.getParams();
		byte[] sig = new byte[dsaParams.getQ().bitLength() / 4];
		read(sig);
		return sig;
	}

	public SignatureX readMysteriousX() throws IOException {
		PublicKey pubKey = readPublicKey();
		int dhKeyID = readInt();
		byte[] sig = readSignature(pubKey);
		return new SignatureX(pubKey, dhKeyID, sig);
	}

	public MessageBase readMessage() throws IOException {
		final byte[] headBytes = new byte[SerializationConstants.HEAD.length];
		in.read(headBytes);

		if (!Arrays.equals(SerializationConstants.HEAD, headBytes)) {
			// Base OTR header not found, handle as plain text.
			// Handle as plaintext, re-construct text bytes (this is important
			// to preserve > 1byte encodings).
			ByteArrayOutputStream out = new ByteArrayOutputStream(in
					.available()
					+ headBytes.length);
			out.write(headBytes);
			int i;
			while ((i = in.read()) > -1)
				out.write(i);

			String text = new String(out.toByteArray());
			out.close();

			// Try to detect whitespace tag.
			final Matcher matcher = patternWhitespace.matcher(text);

			boolean v1 = false;
			boolean v2 = false;
			while (matcher.find()) {
				if (!v1 && matcher.start(2) > -1)
					v1 = true;

				if (!v2 && matcher.start(3) > -1)
					v2 = true;

				if (v1 && v2)
					break;
			}

			String cleanText = matcher.replaceAll("");
			List<Integer> versions;
			if (v1 && v2) {
				versions = new Vector<Integer>(2);
				versions.set(0, 1);
				versions.set(0, 2);
			} else if (v1) {
				versions = new Vector<Integer>(1);
				versions.set(0, 1);
			} else if (v2) {
				versions = new Vector<Integer>(1);
				versions.set(0, 2);
			} else
				versions = null;

			return new PlainTextMessage(versions, cleanText);
		} else {
			byte[] typeHead = new byte[1];
			in.read(typeHead);

			if (Arrays.equals(SerializationConstants.HEAD_ENCODED, typeHead)) {
				String base64 = "";
				int i;
				while ((i = in.read()) > -1)
					base64 += (char) i;

				// TODO: Use a Base64DecoderStream.
				ByteArrayInputStream bin = new ByteArrayInputStream(Base64
						.decode(base64.getBytes()));
				OtrInputStream otr = new OtrInputStream(bin);
				// We have an encoded message.
				int protocolVersion = otr.readShort();
				int messageType = otr.readByte();
				switch (messageType) {
				case EncodedMessageBase.MESSAGE_DATA:
					int flags = otr.readByte();
					int senderKeyID = otr.readInt();
					int recipientKeyID = otr.readInt();
					DHPublicKey nextDH = otr.readDHPublicKey();
					byte[] ctr = otr.readCtr();
					byte[] encryptedMessage = otr.readData();
					byte[] mac = otr.readMac();
					byte[] oldMacKeys = otr.readMac();
					return new DataMessage(protocolVersion, flags, senderKeyID,
							recipientKeyID, nextDH, ctr, encryptedMessage, mac,
							oldMacKeys);
				case EncodedMessageBase.MESSAGE_DH_COMMIT:
					byte[] dhPublicKeyEncrypted = otr.readData();
					byte[] dhPublicKeyHash = otr.readData();
					return new DHCommitMessage(protocolVersion,
							dhPublicKeyHash, dhPublicKeyEncrypted);
				case EncodedMessageBase.MESSAGE_DHKEY:
					DHPublicKey dhPublicKey = otr.readDHPublicKey();
					return new DHKeyMessage(protocolVersion, dhPublicKey);
				case EncodedMessageBase.MESSAGE_REVEALSIG: {
					byte[] revealedKey = otr.readData();
					byte[] xEncrypted = otr.readData();
					byte[] xEncryptedMac = otr.readMac();
					return new RevealSignatureMessage(protocolVersion,
							xEncrypted, xEncryptedMac, revealedKey);
				}
				case EncodedMessageBase.MESSAGE_SIGNATURE: {
					byte[] xEncryted = otr.readData();
					byte[] xEncryptedMac = otr.readMac();
					return new SignatureMessage(protocolVersion, xEncryted,
							xEncryptedMac);
				}
				default:
					throw new IOException("Illegal message type.");
				}
			} else if (Arrays.equals(SerializationConstants.HEAD_ERROR,
					typeHead)) {
				// Handle as plaintext, re-construct text bytes (this is
				// important to
				// preserve > 1byte encodings).

				ByteArrayOutputStream out = new ByteArrayOutputStream(in
						.available());
				int i;
				while ((i = in.read()) > -1)
					out.write(i);

				String text = new String(out.toByteArray());
				out.close();

				return new ErrorMessage(MessageBase.MESSAGE_ERROR, text);
			} else if (Arrays.equals(SerializationConstants.HEAD_QUERY_Q,
					typeHead)) {
				InputStreamReader isr = new InputStreamReader(in);
				OtrQueryReader qois = new OtrQueryReader(isr, false);
				QueryMessage qmsg = qois.readMessage();
				qois.close();
				return qmsg;
			} else if (Arrays.equals(SerializationConstants.HEAD_QUERY_V,
					typeHead)) {
				InputStreamReader isr = new InputStreamReader(in);
				OtrQueryReader qois = new OtrQueryReader(isr, true);
				QueryMessage qmsg = qois.readMessage();
				qois.close();
				return qmsg;
			} else {
				throw new IOException("Uknown message type.");
			}
		}
	}

	static final Pattern patternWhitespace = Pattern
			.compile("( \\t  \\t\\t\\t\\t \\t \\t \\t  )(  \\t\\t  \\t )?( \\t \\t  \\t )?");
}
