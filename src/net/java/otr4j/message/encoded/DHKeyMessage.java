package net.java.otr4j.message.encoded;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.interfaces.DHPublicKey;
import net.java.otr4j.message.MessageType;
import net.java.otr4j.protocol.crypto.CryptoUtils;

public final class DHKeyMessage extends EncodedMessageBase {

	public DHPublicKey gy;
	
	private DHKeyMessage() {
		super(MessageType.DH_KEY);
	}
	
	public DHKeyMessage(int protocolVersion, DHPublicKey gy){
		this();
		
		this.gy = gy;
		this.protocolVersion = protocolVersion;
	}
	
	public String toString(){
		int len = 0;
		// Protocol version (SHORT)
		byte[] protocolVersion = EncodedMessageUtils.serializeShort(this.protocolVersion);
		len += protocolVersion.length;
	
		// Message type (BYTE)
		byte[] messageType = EncodedMessageUtils.serializeByte(this.protocolVersion);
		len += messageType.length;
	
		// gy (MPI)
		byte[] gyMpiSerialized = EncodedMessageUtils.serializeDHPublicKey(this.gy);
		len += gyMpiSerialized.length;
	
		ByteBuffer buff = ByteBuffer.allocate(len);
		buff.put(protocolVersion);
		buff.put(messageType);
		buff.put(gyMpiSerialized);
	
		String encodedMessage = EncodedMessageUtils.encodeMessage(buff.array());
		return encodedMessage;
	}
	
	public DHKeyMessage(String msgText) throws NoSuchAlgorithmException, InvalidKeySpecException{
		this();
		
		byte[] decodedMessage = EncodedMessageUtils.decodeMessage(msgText);
		ByteBuffer buff = ByteBuffer.wrap(decodedMessage);
	
		// Protocol version (SHORT)
		int protocolVersion = EncodedMessageUtils.deserializeShort(buff);
	
		// Message type (BYTE)
		int msgType = EncodedMessageUtils.deserializeByte(buff);
		if (msgType != MessageType.DH_KEY)
			return;
	
		// gy (MPI)
		BigInteger gyMpi = EncodedMessageUtils.deserializeMpi(buff);
		DHPublicKey gy = CryptoUtils.getDHPublicKey(gyMpi);
		
		this.protocolVersion = protocolVersion;
		this.gy = gy;
	}
}
