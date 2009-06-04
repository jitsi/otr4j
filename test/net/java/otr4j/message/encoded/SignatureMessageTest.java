package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.security.KeyPair;
import javax.crypto.interfaces.DHPublicKey;

import org.junit.Test;

import junit.framework.TestCase;

public final class SignatureMessageTest extends TestCase {

	@Test
	public void testCreate() throws Exception {
		// Prepare arguments.
		KeyPair dhKeyPairX = Utils.generateDHKeyPair();
		KeyPair dhKeyPairY = Utils.generateDHKeyPair();
		int keyidB = 1;
		KeyPair keyPair = Utils.generateDsaKeyPair();
		int protocolVersion = 2;

		BigInteger s = Utils.getSecretKey(dhKeyPairX, dhKeyPairY);

		byte[] cp = Utils.getCp(s);
		byte[] m1p = Utils.getM1p(s);
		byte[] m2p = Utils.getM2p(s);
		SignatureMessage msg = SignatureMessage.create(protocolVersion,
				(DHPublicKey) dhKeyPairX.getPublic(), (DHPublicKey) dhKeyPairY
						.getPublic(), keyidB, keyPair.getPrivate(), keyPair
						.getPublic(), cp, m1p, m2p);

		assertNotNull(msg);

	}

	private static String SignatureMessageText = "?OTR:AAISAAAB0r0CzJSXTbcMeSVFQ/9kSPNW7P9BLYGn2zfIJALhXU0L8jGxUce4sZWNKhPA8QF8duBHlV1rXrZjJqSyYFaFQV1uAU6WrdgCus9T2cqqDE0VICwzHfbiz/RNt0FZSERGNtmLF/qHY+yHZwOKI4P3F9XP9/OSSCixSo1dRa8JxrPAgyYU8Y9bNudRTnIgdaKpCX0wVXcIe2Axp0Ni0YXmDSUAJACfiY9ShGjW2d3HPZiDLvlJVW44Fp73lijJQWXmxXQ6tu59yTyNyAqZUMqbSiM6HukH8wuLTHVWkWN63KdxdXC9OAMXMTHTECmDuK9oD5/LFTZOGTQ202g5p4Mbkokbh2fMW7GhpLwAT8Y4De5sy9DfFotobjHBKktxnF+z/LYDcNQyY6EE2iLK0R4qLzrNZA4uifePZAhqawx5fKfd30b8xUIMEjobTm2Cz4osjYyUMRtQWtNjsG2wp3m4nQ+lJfLwtfWg53og8o/kidulGuEiCg3CYSfT2Mzw5o9t5kswBdnRWwUvP6VNP3s6mOFg2s3WZ7HTisK7IWOyEfilyTa7IMGxwDriDayykaXZA5/x+7LZFHy7qNOTxt1cWQ1+Elr4NKYwSOXe6H7LtCb/4GiKxEwB8qnthM2xLxbvZuIGC0qbqQ==.";

	@Test
	public void testDisassemble() {
		SignatureMessage signatureMessage = SignatureMessage
				.disassemble(SignatureMessageText);
		assertNotNull(signatureMessage);
	}

}
