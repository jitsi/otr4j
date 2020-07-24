package net.java.otr4j.crypto;

import java.security.InvalidKeyException;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assume.assumeNoException;

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

    @Test
    public void testDSAConvertSignatures() throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, OtrCryptoException {
        final KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA");
        kg.initialize(1024);
        final KeyPair keypair = kg.genKeyPair();

        final byte[] data = new byte[20];
        final Signature signerASN = Signature.getInstance("NONEwithDSA");
        final Signature verifierASN = Signature.getInstance("NONEwithDSA");
        final Signature signerP1363;
        final Signature verifierP1363;
        try {
            signerP1363 = Signature.getInstance("NONEwithDSAinP1363Format");
            verifierP1363 = Signature.getInstance("NONEwithDSAinP1363Format");
        } catch (final NoSuchAlgorithmException ex) {
            assumeNoException("Signature algorith NONEwithDSAinP1363Format is not available, so ASN.1 to P1363 "
                    + "conversion cannot be verified.", ex);
            return;
        }
        for (int i = 0; i < 1000; i++) {
            RANDOM.nextBytes(data);

            signerASN.initSign(keypair.getPrivate());
            signerP1363.initSign(keypair.getPrivate());
            signerASN.update(data);
            signerP1363.update(data);

            final byte[] signatureASN = signerASN.sign();
            final byte[] signatureP1363 = signerP1363.sign();

            verifierP1363.initVerify(keypair.getPublic());
            verifierASN.initVerify(keypair.getPublic());
            verifierP1363.update(data);
            verifierASN.update(data);

            final byte[] convertedP1363 = CRYPTO.convertSignatureASN1ToP1363(signatureASN);
            assertTrue(Util.bytesToHexString(signatureASN) + " failed conversion to P1363: "
                    + Util.bytesToHexString(convertedP1363), verifierP1363.verify(convertedP1363));
            
            final byte[] convertedASN = CRYPTO.convertSignatureP1363ToASN1(signatureP1363);
            assertTrue(Util.bytesToHexString(signatureP1363) + " failed conversion to ASN.1: "
                    + Util.bytesToHexString(convertedASN), verifierASN.verify(convertedASN));
        }
    }
}
