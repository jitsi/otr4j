package net.java.otr4j;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;

import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;

public class MysteriousXUtils {
	public static BigInteger[] sign(byte[] b, PrivateKey privatekey)
			throws NoSuchAlgorithmException, InvalidKeyException,
			SignatureException {
		
		DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) privatekey;
		DSAParams auxDsaParams = dsaPrivateKey.getParams();
		
		// TODO JCE Usage ends here... Wondering if there's a JCE way of doing this?
		DSAParameters dsaParams = new DSAParameters(auxDsaParams.getP(),
				auxDsaParams.getQ(), auxDsaParams.getG());
		DSAPrivateKeyParameters dsaParamsPrivatekey = new DSAPrivateKeyParameters(
				dsaPrivateKey.getX(), dsaParams);

		DSASigner dsaSigner = new DSASigner();
		dsaSigner.init(true, dsaParamsPrivatekey);
		return dsaSigner.generateSignature(b);
	}
}
