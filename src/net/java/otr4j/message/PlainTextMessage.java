package net.java.otr4j.message;

import java.util.Vector;



public final class PlainTextMessage extends QueryMessageBase {

	private String cleanText;
	
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
		
		this.setVersions(versions);
		this.setCleanText(cleanText);
	}

	public void setCleanText(String cleanText) {
		this.cleanText = cleanText;
	}

	public String getCleanText() {
		return cleanText;
	}
}