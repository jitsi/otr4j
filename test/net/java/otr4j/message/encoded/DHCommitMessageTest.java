package net.java.otr4j.message.encoded;

import java.security.KeyPair;

import javax.crypto.interfaces.DHPublicKey;

import junit.framework.TestCase;
import net.java.otr4j.message.encoded.CryptoConstants;
import net.java.otr4j.message.encoded.DHCommitMessage;
import org.junit.Test;

public class DHCommitMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {
		// Prepare arguments.
		KeyPair keyPair = Utils.generateDHKeyPair();
		byte[] r = Utils.getRandomBytes(CryptoConstants.AES_KEY_BYTE_LENGTH);
		int protocolVersion = 2;

		DHCommitMessage dhCommitMessage = DHCommitMessage.create(
				protocolVersion, r, (DHPublicKey) keyPair.getPublic());

		assertNotNull(dhCommitMessage);

	}

	private static String DHCommitMessageText = "?OTR:AAICAAAAxM277nE7lEH30XWAryFZW4WDW2BUKE4fK/PFJcFGGyR7Z3SoIviHLphSDudtgiflruKOJ3PoeTV7py5fa0JwsvpDRjkSR9Fa5qfePlG7PfYSoSzYb81VJzIOK38gPH0TeG4/FNx7ywM3vFm0nGXkfmAICtp6BAZpM4WUFnWhB2rl1VTzo2YoUdspTXSHiEt3FSu5oo3EsF0TAmimMRBSB4AZH0R5WgBcxUVEtJOa6WIJ6HhJ/zjoh18vJgjAAN9kpJkuEbQAAAAgQLGeTiq4iYf91VxTPHw0T1arydZuMYK16y6DrAizgfo=.";

	@Test
	public void testDisassemble() {
		DHCommitMessage dhCommitMessage = DHCommitMessage
				.disassemble(DHCommitMessageText);
		assertNotNull(dhCommitMessage);
	}

}
