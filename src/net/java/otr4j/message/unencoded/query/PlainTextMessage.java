package net.java.otr4j.message.unencoded.query;

import java.util.*;

import net.java.otr4j.message.*;
import net.java.otr4j.message.unencoded.*;

public final class PlainTextMessage extends QueryMessageBase {

	public String cleanText;
	
	public PlainTextMessage (String msgText) {
		this.setMessageType(MessageType.PLAINTEXT);
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
		
		this.versions = versions;
		this.cleanText = cleanText;
	}
}