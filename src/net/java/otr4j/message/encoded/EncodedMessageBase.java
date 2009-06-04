package net.java.otr4j.message.encoded;

import net.java.otr4j.message.MessageBase;

/**
 * <pre>
 * Encoded messages
 * 
 * This section describes the byte-level format of the base-64 encoded binary OTR messages. The binary form of each of the messages is described below. To transmit one of these messages, construct the ASCII string consisting of the five bytes &quot;?OTR:&quot;, followed by the base-64 encoding of the binary form of the message, followed by the byte &quot;.&quot;.
 * 
 * For the Diffie-Hellman group computations, the group is the one defined in RFC 3526 with 1536-bit modulus (hex, big-endian):
 * 
 *     FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
 *     29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
 *     EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
 *     E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
 *     EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
 *     C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
 *     83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
 *     670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
 * 
 * and a generator (g) of 2. Note that this means that whenever you see a Diffie-Hellman exponentiation in this document, it always means that the exponentiation is done modulo the above 1536-bit number.
 * </pre>
 * 
 * @author george
 * 
 */
public abstract class EncodedMessageBase extends MessageBase {

	protected EncodedMessageBase(int messageType) {
		super(messageType);
	}

	// TODO Decide if this should this be a character
	private int protocolVersion;

	protected void setProtocolVersion(int protocolVersion) {
		this.protocolVersion = protocolVersion;
	}

	public int getProtocolVersion() {
		return protocolVersion;
	}
}
