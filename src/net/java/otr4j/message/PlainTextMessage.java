package net.java.otr4j.message;

import java.io.IOException;
import java.util.Vector;

public final class PlainTextMessage extends QueryMessageBase {

	private String cleanText;

	public PlainTextMessage(String text, Vector<Integer> versions) {
		super(MessageConstants.PLAINTEXT);
		this.setCleanText(text);
		this.setVersions(versions);
	}

	public PlainTextMessage() {
		super(MessageConstants.PLAINTEXT);
	}

	private void setCleanText(String cleanText) {
		this.cleanText = cleanText;
	}

	public String getCleanText() {
		return cleanText;
	}

	public void readObject(String msgText) throws IOException {
		Vector<Integer> versions = new Vector<Integer>();

		String cleanText = msgText;
		if (msgText.contains(MessageConstants.BASE)) {
			cleanText = cleanText.replace(MessageConstants.BASE, "");
			// We have a base tag
			if (msgText.contains(MessageConstants.V1)) {
				cleanText = cleanText.replace(MessageConstants.V1, "");
				versions.add(1);
			}

			if (msgText.contains(MessageConstants.V2)) {
				cleanText = cleanText.replace(MessageConstants.V2, "");
				versions.add(2);
			}
		}

		this.setVersions(versions);
		this.setCleanText(cleanText);
	}

	public String writeObject() throws IOException {
		String text = this.getCleanText();
		Vector<Integer> versions = this.getVersions();
		
		if (versions != null && versions.size() > 0) {
			text += MessageConstants.BASE;
			if (versions.contains(1))
				text += MessageConstants.V1;

			if (versions.contains(2))
				text += MessageConstants.V2;
		}
		
		return text;
	}
}