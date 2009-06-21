package net.java.otr4j.message.unencoded.query;

import java.util.Vector;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

public final class QueryMessage extends QueryMessageBase {

	public String toString() {
		String txt = MessageHeader.BASE + "?";

		for (int version : versions) {
			txt += version;
		}

		txt += "?";
		return txt;
	}

	public QueryMessage(Vector<Integer> versions) {
		this.messageType = MessageType.QUERY;
		this.versions = versions;
	}

	public QueryMessage(String msgText) {
		if (!msgText.startsWith(MessageHeader.QUERY1)
				&& !msgText.startsWith(MessageHeader.QUERY2))
			return;

		this.messageType = MessageType.QUERY;
		msgText = msgText.substring(MessageHeader.BASE.length());
		char[] chars = msgText.toCharArray();
		Vector<Integer> versions = new Vector<Integer>();
		Boolean stop = false;
		for (int i = 0; i < chars.length; i++) {
			char c = chars[i];
			switch (c) {
			case 'V':
			case 'v':
				// Ignore, signifies version numbers will follow.
				break;
			case '?':
				if (i == 0) {
					// Signifies Version 1.
					versions.add(1);
					if (chars.length == 1)
						stop = true;
				} else {
					// Signifies end of version description
					stop = true;
				}
				break;
			default:
				// Control chars are v and ?, everything else should be version
				// descriptors, but no character versions exists, so skip the
				// evil character.
				try {
					versions.add(Integer.parseInt(String.valueOf(c)));
				} catch (NumberFormatException ex) {
					continue;
				}
			}

			if (stop)
				break;
		}

		this.versions = versions;
	}

}
