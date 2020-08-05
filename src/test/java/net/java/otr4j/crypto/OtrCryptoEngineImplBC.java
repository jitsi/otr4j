package net.java.otr4j.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

/**
 * This class contains previous implementations of OtrCryptoEngine which relied on the Bouncy Castle library.
 * These are now used to test cross-library compatibility, and specifically that cryptographic primitives are used
 * correctly.
 */
final class OtrCryptoEngineImplBC {

    private OtrCryptoEngineImplBC() {
        // no need to instantiate utility
    }

    static byte[] aesDecrypt(byte[] key, byte[] ctr, byte[] b) throws OtrCryptoException {
        BufferedBlockCipher bufSicAesDec = new BufferedBlockCipher(new SICBlockCipher(new AESEngine()));

        // Create initial counter value 0.
        if (ctr == null)
            ctr = new byte[OtrCryptoEngine.AES_CTR_BYTE_LENGTH];
        bufSicAesDec.init(false, new ParametersWithIV(new KeyParameter(key), ctr));
        byte[] aesOutLwDec = new byte[b.length];
        int done = bufSicAesDec.processBytes(b, 0, b.length, aesOutLwDec, 0);
        try {
            bufSicAesDec.doFinal(aesOutLwDec, done);
        } catch (InvalidCipherTextException e) {
            throw new OtrCryptoException(e);
        }
        return aesOutLwDec;
    }

    static byte[] aesEncrypt(byte[] key, byte[] ctr, byte[] b) throws OtrCryptoException {
        BufferedBlockCipher bufSicAesEnc = new BufferedBlockCipher(new SICBlockCipher(new AESEngine()));

        // Create initial counter value 0.
        if (ctr == null)
            ctr = new byte[OtrCryptoEngine.AES_CTR_BYTE_LENGTH];
        bufSicAesEnc.init(true, new ParametersWithIV(new KeyParameter(key), ctr));
        byte[] aesOutLwEnc = new byte[b.length];
        int done = bufSicAesEnc.processBytes(b, 0, b.length, aesOutLwEnc, 0);
        try {
            bufSicAesEnc.doFinal(aesOutLwEnc, done);
        } catch (InvalidCipherTextException e) {
            throw new OtrCryptoException(e);
        }
        return aesOutLwEnc;
    }

    static byte[] sign(byte[] b, DSAPrivateKey privatekey) {
        DSAParams dsaParams = privatekey.getParams();
        DSAParameters bcDSAParameters = new DSAParameters(dsaParams.getP(),
                dsaParams.getQ(), dsaParams.getG());

        DSAPrivateKeyParameters bcDSAPrivateKeyParms = new DSAPrivateKeyParameters(
                privatekey.getX(), bcDSAParameters);

        DSASigner dsaSigner = new DSASigner();
        dsaSigner.init(true, bcDSAPrivateKeyParms);

        BigInteger q = dsaParams.getQ();

        // Ian: Note that if you can get the standard DSA implementation you're
        // using to not hash its input, you should be able to pass it ((256-bit
        // value) mod q), (rather than truncating the 256-bit value) and all
        // should be well.
        // ref: Interop problems with libotr - DSA signature
        BigInteger bmpi = new BigInteger(1, b);
        BigInteger[] rs = dsaSigner.generateSignature(BigIntegers
                .asUnsignedByteArray(bmpi.mod(q)));

        int siglen = q.bitLength() / 4;
        int rslen = siglen / 2;
        byte[] rb = BigIntegers.asUnsignedByteArray(rs[0]);
        byte[] sb = BigIntegers.asUnsignedByteArray(rs[1]);

        // Create the final signature array, padded with zeros if necessary.
        byte[] sig = new byte[siglen];
        System.arraycopy(rb, 0, sig, rslen - rb.length, rb.length);
        System.arraycopy(sb, 0, sig, sig.length - sb.length, sb.length);
        return sig;
    }

    static boolean verify(byte[] b, DSAPublicKey pubKey, byte[] rs) {
        DSAParams dsaParams = pubKey.getParams();
        int qlen = dsaParams.getQ().bitLength() / 8;
        ByteBuffer buff = ByteBuffer.wrap(rs);
        byte[] r = new byte[qlen];
        buff.get(r);
        byte[] s = new byte[qlen];
        buff.get(s);
        return verify(b, pubKey, r, s);
    }

    private static boolean verify(byte[] b, DSAPublicKey pubKey, byte[] r, byte[] s) {
        return verify(b, pubKey, new BigInteger(1, r), new BigInteger(1, s));
    }

    private static boolean verify(byte[] b, DSAPublicKey pubKey, BigInteger r, BigInteger s) {
        DSAParams dsaParams = pubKey.getParams();

        BigInteger q = dsaParams.getQ();
        DSAParameters bcDSAParams = new DSAParameters(dsaParams.getP(), q,
                dsaParams.getG());

        DSAPublicKeyParameters dsaPrivParms = new DSAPublicKeyParameters(
                pubKey.getY(), bcDSAParams);

        // Ian: Note that if you can get the standard DSA implementation you're
        // using to not hash its input, you should be able to pass it ((256-bit
        // value) mod q), (rather than truncating the 256-bit value) and all
        // should be well.
        // ref: Interop problems with libotr - DSA signature
        DSASigner dsaSigner = new DSASigner();
        dsaSigner.init(false, dsaPrivParms);

        BigInteger bmpi = new BigInteger(1, b);
        return dsaSigner.verifySignature(BigIntegers
                .asUnsignedByteArray(bmpi.mod(q)), r, s);
    }
}
