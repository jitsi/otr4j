package net.java.otr4j.message;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

@SuppressWarnings("serial")
public class OtrInteger extends OtrWrappedType<Integer> {

	public OtrInteger(Integer prim) {
		super(prim);
	}

	public void writeObject(OutputStream out) throws IOException {

	}

	public void readObject(InputStream in) throws IOException {

	}
}
