package net.java.otr4j.message.encoded;

import junit.framework.TestCase;
import net.java.otr4j.message.encoded.DHCommitMessage;

import org.junit.Test;

public class DHCommitMessageTest extends TestCase {

	@Test
	public void testDisassemble() {
		DHCommitMessage dhCommitMessage = new DHCommitMessage(
				EncodedMessageTextSample.DHCommitMessageText);
		assertNotNull(dhCommitMessage);
	}

}
