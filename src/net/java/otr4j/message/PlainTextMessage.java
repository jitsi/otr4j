package net.java.otr4j.message;

import java.util.*;

public final class PlainTextMessage extends QueryMessageBase {

	public String cleanText;
	
	public PlainTextMessage (String msgText) {
		super(MessageConstants.PLAINTEXT);
		Vector<Integer> versions = new Vector<Integer>();
		
		String cleanText = msgText;
		if (msgText.contains(MessageConstants.BASE))
		{
			cleanText = cleanText.replace(MessageConstants.BASE, "");
			// We have a base tag
			if (msgText.contains(MessageConstants.V1))
			{
				cleanText = cleanText.replace(MessageConstants.V1, "");
				versions.add(1);
			}
			
			if (msgText.contains(MessageConstants.V2))
			{
				cleanText = cleanText.replace(MessageConstants.V2, "");
				versions.add(2);
			}
		}
		
		this.versions = versions;
		this.cleanText = cleanText;
	}
}