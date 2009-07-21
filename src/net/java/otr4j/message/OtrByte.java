package net.java.otr4j.message;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

@SuppressWarnings("serial")
public class OtrByte extends OtrWrappedType<Byte> {

	public OtrByte(Byte prim) {
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
