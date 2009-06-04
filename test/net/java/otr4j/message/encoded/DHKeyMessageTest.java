package net.java.otr4j.message.encoded;

import java.security.KeyPair;

import javax.crypto.interfaces.DHPublicKey;

import org.junit.Test;

import junit.framework.TestCase;

import net.java.otr4j.message.encoded.DHKeyMessage;

public class DHKeyMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {

		// Prepare parameters.
		KeyPair keyPair = Utils.generateDHKeyPair();
		int protocolVersion = 2;

		DHKeyMessage dhKeyMessage = DHKeyMessage.create(protocolVersion,
				(DHPublicKey) keyPair.getPublic());

		assertNotNull(dhKeyMessage);
	}

	private static String DHKeyMessageText = "?OTR:AAIKAAAAwDQlc11etGIBTSMB/rI9hgRTWfIfWhA+jmgDwpUDjdh8uilY0UXPrcH17+/9cRUjWxQdObavVNICPpuwHra2Xnz0S9nq6IRW2Fq9yaH51vg8AEliqHaDqfr5cMBFEAIqfJFC8v5IvMN4pfehHWgh+fjMHujXZYzJOTv2KXwq8GtD9kq2xIsCOglZ6aQ/jpHq0PoGdLfw1oD8DBvjWI7iJcg7pu2jL4WeEp6bxLcJqrYHob18qxCmKAwYvj8ScIkgPA==.";

	@Test
	public void testDisassemble() throws Exception {
		DHKeyMessage dhKeyMessage = DHKeyMessage.disassemble(DHKeyMessageText);
		assertNotNull(dhKeyMessage);
	}

}
