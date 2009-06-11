package net.java.otr4j.protocol.crypto;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class DHKeyPairContainer {
	public KeyPair pair;
	public byte[] publicHash;
	
	public DHKeyPairContainer(KeyPair pair) throws NoSuchAlgorithmException {
		this.publicHash = CryptoUtils.sha256Hash(pair.getPublic().getEncoded());
		this.pair = pair;
	}
}
