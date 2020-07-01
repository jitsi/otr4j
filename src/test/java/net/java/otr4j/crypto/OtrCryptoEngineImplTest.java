package net.java.otr4j.crypto;

import org.junit.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import static org.junit.Assert.*;
import static org.junit.Assert.assertArrayEquals;

public class OtrCryptoEngineImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final OtrCryptoEngineImpl CRYPTO = new OtrCryptoEngineImpl();

    @Test
    public void testAESEncryptionDecryptionInterop() throws OtrCryptoException {
        final byte[] key = new byte[OtrCryptoEngineImpl.AES_KEY_BYTE_LENGTH];
        RANDOM.nextBytes(key);
        final byte[] ctr = new byte[OtrCryptoEngineImpl.AES_CTR_BYTE_LENGTH];
        RANDOM.nextBytes(ctr);

        final byte[] data = new byte[RANDOM.nextInt(4096)];
        RANDOM.nextBytes(data);

        final byte[] ciphertextJCA = CRYPTO.aesEncrypt(key, ctr, data);
        final byte[] ciphertextBC = OtrCryptoEngineImplBC.aesEncrypt(key, ctr, data);
        assertArrayEquals(ciphertextJCA, ciphertextBC);

        final byte[] plaintextJCA = OtrCryptoEngineImplBC.aesDecrypt(key, ctr, ciphertextJCA);
        final byte[] plaintextBC = CRYPTO.aesEncrypt(key, ctr, ciphertextBC);
        assertArrayEquals(plaintextJCA, data);
        assertArrayEquals(plaintextBC, data);
    }

    @Test
    public void testDSASigningInterop() throws OtrCryptoException {
        final KeyPair keypair = CRYPTO.generateDSAKeyPair();

        final byte[] data = new byte[RANDOM.nextInt(120) + 1];
        RANDOM.nextBytes(data);

        final byte[] sigJCA = CRYPTO.sign(data, keypair.getPrivate());
        final byte[] sigBC = OtrCryptoEngineImplBC.sign(data, (DSAPrivateKey) keypair.getPrivate());

        // verify signatures using the alternative verification function
        assertTrue(CRYPTO.verify(data, keypair.getPublic(), sigBC));
        assertTrue(OtrCryptoEngineImplBC.verify(data, (DSAPublicKey) keypair.getPublic(), sigJCA));

        // now corrupt original data and check if verification fails
        data[RANDOM.nextInt(data.length)] ^= (byte) (RANDOM.nextInt(255) + 1);
        assertFalse(CRYPTO.verify(data, keypair.getPublic(), sigBC));
        assertFalse(OtrCryptoEngineImplBC.verify(data, (DSAPublicKey) keypair.getPublic(), sigJCA));
    }
}