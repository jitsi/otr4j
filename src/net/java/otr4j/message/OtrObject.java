package net.java.otr4j.message;

import java.io.*;

@SuppressWarnings("serial")
public abstract class OtrObject implements Serializable {
	
	public abstract void writeObject(OutputStream out) throws IOException;
	public abstract void readObject(InputStream in) throws IOException;
	
}
