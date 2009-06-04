package net.java.otr4j.message.unencoded;

import java.util.Vector;

import net.java.otr4j.message.MessageType;

/**
 * <pre>
 * Tagged plaintext messages
 * 
 * If Alice wishes to communicate to Bob that she is willing to use OTR, she can attach a special whitespace tag to any plaintext message she sends him. This tag may occur anywhere in the message, and may be hidden from the user (as in the Query Messages, above).
 * 
 * The tag consists of the following 16 bytes, followed by one or more sets of 8 bytes indicating the version of OTR Alice is willing to use:
 * 
 * Always send &quot;\x20\x09\x20\x20\x09\x09\x09\x09&quot; &quot;\x20\x09\x20\x09\x20\x09\x20\x20&quot;, followed by one or more of:
 * &quot;\x20\x09\x20\x09\x20\x20\x09\x20&quot; to indicate a willingness to use OTR version 1 with Bob (note: this string must come before all other whitespace version tags, if it is present, for backwards compatibility)
 * &quot;\x20\x20\x09\x09\x20\x20\x09\x20&quot; to indicate a willingness to use OTR version 2 with Bob
 * 
 * If Bob is willing to use OTR with Alice (with a protocol version that Alice has offered), he should start the AKE. On the other hand, if Alice receives a plaintext message from Bob (rather than an initiation of the AKE), she should stop sending him the whitespace tag.
 * </pre>
 * 
 * @author george
 * 
 */
public final class PlainTextMessage extends DiscoveryMessageBase {

	private PlainTextMessage() {
		super(MessageType.PLAINTEXT);
	}

	private String cleanText;
	
	public static PlainTextMessage disassemble(String msgText) {
		Vector<Integer> versions = new Vector<Integer>();
		
		String cleanText = msgText;
		if (msgText.contains(WhiteSpaceTag.BASE))
		{
			cleanText = cleanText.replace(WhiteSpaceTag.BASE, "");
			// We have a base tag
			if (msgText.contains(WhiteSpaceTag.V1))
			{
				cleanText = cleanText.replace(WhiteSpaceTag.V1, "");
				versions.add(1);
			}
			
			if (msgText.contains(WhiteSpaceTag.V2))
			{
				cleanText = cleanText.replace(WhiteSpaceTag.V2, "");
				versions.add(2);
			}
		}
		
		PlainTextMessage msg = new PlainTextMessage();
		
		msg.setVersions(versions);
		msg.setCleanText(cleanText);
		return msg;
	}

	private void setCleanText(String cleanText) {
		this.cleanText = cleanText;
	}

	public String getCleanText() {
		return cleanText;
	}
}