package net.java.otr4j;

import java.io.IOException;

public interface OtrSerializable {
	public void readObject(byte[] b) throws IOException;

	public void readObject(java.io.ByteArrayInputStream in) throws IOException;
	
	public void writeObject(java.io.ByteArrayOutputStream out) throws IOException;
}
