package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.security.KeyPair;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;

import junit.framework.TestCase;

import net.java.otr4j.message.encoded.CryptoConstants;
import net.java.otr4j.message.encoded.RevealSignatureMessage;
import org.junit.Test;

public class RevealSignatureMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {

		// Prepare arguments.
		KeyPair dhKeyPairX = Utils.generateDHKeyPair();
		KeyPair dhKeyPairY = Utils.generateDHKeyPair();
		int keyidB = 1;
		KeyPair dsaKeyPair = Utils.generateDsaKeyPair();
		int protocolVersion = 2;

		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(dhKeyPairX.getPrivate());
		ka.doPhase(dhKeyPairY.getPublic(), true);
		BigInteger s = new BigInteger(ka.generateSecret());

		byte[] c = Utils.getCp(s);
		byte[] m1 = Utils.getM1p(s);
		byte[] m2 = Utils.getM2p(s);

		byte[] r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);

		RevealSignatureMessage msg = RevealSignatureMessage.create(
				protocolVersion, (DHPublicKey) dhKeyPairX.getPublic(),
				(DHPublicKey) dhKeyPairY.getPublic(), keyidB, dsaKeyPair
						.getPrivate(), dsaKeyPair.getPublic(), c, m1, m2, r);

		assertNotNull(msg);

	}

	private static String RevealSignatureMessageText = "?OTR:AAIRAAAAEBpB31X97veB2M9tUUiU7pkAAAHSPp5PTQpf+akbmE0aBPViimS1S4t1HWCjtyNg+Sgd9ZoeaQIG5me2VRTqDJHb/ZF2cV0ru/uWUmRObXwtm+URnWEYWRuwUr2Q/2A2Ueo7eYfbOG3sOQrqFK4XWHesduhAzrGKGlZ0bjlHyi6C/+4eli8KsnFe7ii9fV6gYPBsTDevr8taPdh0JYfwB6F3NEPiT6sv/jskfGeVkjYvIQZ6KNUmcF5eXn6kOWqEq/67KWtWpiFJ92qAdCJjhDnwOlxSxaL4wHJd3dSgWU5XCQv18eoUpleCNrQCjNxLsZFTibee38wKx6Mq2eMkpjvqmhrD13t9iGEFWS5Gp4AezaLooTPXlJ6I1vB8288oG+06h6Nx1KkgUrLGwuUWL0BAamgxuqraf1G3SlxY3sU3/KRyMHAtBdufGJSydpgeKRyi0jl240q8FhVtIE8ysPJGmORs9+skP8qnY8Ljdp1TQGq19aNyrS02AuK9hegpEubmUmyv8jpqPIpj98RvjqfREyd5PreGDC7i8Z/SfdiHR/PgpW1yUdBSxqMFfOXCb/VlhgNXwBjXvYuS1Xk8GZz67q25QahD1S2znzzKX6bOd2w0ubwCOZ8PowDFPcmT2aPE7Ke14zPijVLJ2uoT3whSO1LMONpy/f87.";

	@Test
	public void testDisassemble() {
		RevealSignatureMessage revealSignatureMessage = RevealSignatureMessage
				.disassemble(RevealSignatureMessageText);
		assertNotNull(revealSignatureMessage);
	}

}
