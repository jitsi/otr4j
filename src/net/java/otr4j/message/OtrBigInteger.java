package net.java.otr4j.message;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

@SuppressWarnings("serial")
public class OtrBigInteger extends OtrWrappedType<BigInteger> {

	public OtrBigInteger(BigInteger prim) {
		super(prim);
	}

	@Override
	public void readObject(InputStream in) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void writeObject(OutputStream out) throws IOException {
		// TODO Auto-generated method stub

	}

}
