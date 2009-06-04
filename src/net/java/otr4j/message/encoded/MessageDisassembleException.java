package net.java.otr4j.message.encoded;

public class MessageDisassembleException extends Exception {

	private static final long serialVersionUID = 1L;
	
	public MessageDisassembleException(Exception innerException)
	{
		super (innerException);
	}
}
