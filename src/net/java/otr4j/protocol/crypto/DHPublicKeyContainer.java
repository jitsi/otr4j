package net.java.otr4j.protocol.crypto;

import java.security.NoSuchAlgorithmException;
import javax.crypto.interfaces.DHPublicKey;

public class DHPublicKeyContainer {
	public byte[] hash;
	public DHPublicKey key;
	public DHPublicKeyContainer(DHPublicKey key) throws NoSuchAlgorithmException {
		this.hash = CryptoUtils.sha256Hash(key.getEncoded());
		this.key = key;
	}
}
