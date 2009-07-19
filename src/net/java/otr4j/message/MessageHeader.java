package net.java.otr4j.message;

public class MessageHeader {
	public static final String BASE = "?OTR";
	public static final String ENCODED_MESSAGE = "?OTR:";
	public static final String DH_COMMIT = "?OTR:AAIC";
	public static final String DH_KEY = "?OTR:AAIK";
	public static final String REVEALSIG = "?OTR:AAIR";
	public static final String SIGNATURE = "?OTR:AAIS";
	public static final String ERROR = "?OTR Error:";
	public static final String QUERY1 = "?OTR?";
	public static final String QUERY2 = "?OTRv";
	public static final String DATA1 = "?OTR:AAED";
	public static final String DATA2 = "?OTR:AAID";
	public static final String V1_KEY_EXCHANGE = "?OTR:AAEK";
	
	public static int getMessageType(String msgText) {
		int msgType = 0;
		if (!msgText.startsWith(BASE)) {
			msgType = MessageType.PLAINTEXT;
		} else if (msgText.startsWith(DH_COMMIT)) {
			msgType = MessageType.DH_COMMIT;
		} else if (msgText.startsWith(DH_KEY)) {
			msgType = MessageType.DH_KEY;
		} else if (msgText.startsWith(REVEALSIG)) {
			msgType = MessageType.REVEALSIG;
		} else if (msgText.startsWith(SIGNATURE)) {
			msgType = MessageType.SIGNATURE;
		} else if (msgText.startsWith(V1_KEY_EXCHANGE)) {
			msgType = MessageType.V1_KEY_EXCHANGE;
		} else if (msgText.startsWith(DATA1)
				|| msgText.startsWith(DATA2)) {
			msgType = MessageType.DATA;
		} else if (msgText.startsWith(ERROR)) {
			msgType = MessageType.ERROR;
		} else if (msgText.startsWith(QUERY1)
				|| msgText.startsWith(QUERY2)) {
			msgType = MessageType.QUERY;
		} else {
			msgType = MessageType.UKNOWN;
		}
	
		return msgType;
	}
}
