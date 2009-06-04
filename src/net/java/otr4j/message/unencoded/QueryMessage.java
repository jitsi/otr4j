package net.java.otr4j.message.unencoded;

import java.util.Vector;

import net.java.otr4j.message.MessageHeader;
import net.java.otr4j.message.MessageType;

/**
 * <pre>
 * OTR Query Messages
 * 
 * If Alice wishes to communicate to Bob that she would like to use OTR, she sends a message containing the string &quot;?OTR&quot; followed by an indication of what versions of OTR she is willing to use with Bob. The version string is constructed as follows:
 * 
 * If she is willing to use OTR version 1, the version string must start with &quot;?&quot;.
 * If she is willing to use OTR versions other than 1, a &quot;v&quot; followed by the byte identifiers for the versions in question, followed by &quot;?&quot;. The byte identifier for OTR version 2 is &quot;2&quot;. The order of the identifiers between the &quot;v&quot; and the &quot;?&quot; does not matter, but none should be listed more than once.
 * 
 * For example:
 * 
 * &quot;?OTR?&quot;
 *     Version 1 only
 * &quot;?OTRv2?&quot;
 *     Version 2 only
 * &quot;?OTR?v2?&quot;
 *     Versions 1 and 2
 * &quot;?OTRv24x?&quot;
 *     Version 2, and hypothetical future versions identified by &quot;4&quot; and &quot;x&quot;
 * &quot;?OTR?v24x?&quot;
 *     Versions 1, 2, and hypothetical future versions identified by &quot;4&quot; and &quot;x&quot;
 * &quot;?OTR?v?&quot;
 *     Also version 1 only
 * &quot;?OTRv?&quot;
 *     A bizarre claim that Alice would like to start an OTR conversation, but is unwilling to speak any version of the protocol
 * 
 * These strings may be hidden from the user (for example, in an attribute of an HTML tag), and/or may be accompanied by an explanitory message (&quot;Alice has requested an Off-the-Record private conversation.&quot;). If Bob is willing to use OTR with Alice (with a protocol version that Alice has offered), he should start the AKE.
 * </pre>
 * 
 * @author george
 * 
 */
public final class QueryMessage extends DiscoveryMessageBase {

	private QueryMessage() {
		super(MessageType.QUERY);
	}
	
	public static String assemble(QueryMessage msg){
		// TODO Implement
		return "";
	}
	
	public static QueryMessage create(Vector<Integer> protocolVersions){
		QueryMessage msg = new QueryMessage();
		msg.setVersions(protocolVersions);
		return msg;
	}
	
	public static QueryMessage disassemble(String msgText) {
		if (!msgText.startsWith(MessageHeader.QUERY1)
				&& !msgText.startsWith(MessageHeader.QUERY2))
			return null;

		msgText = msgText.substring(MessageHeader.BASE.length());
		char[] chars = msgText.toCharArray();
		Vector<Integer> versionList = new Vector<Integer>();
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
					versionList.add(1);
					if (chars.length == 1)
						stop = true;
				} else {
					// Signifies end of version description
					stop = true;
				}
				break;
			default:
				// Control chars are v and ?, everything else should be version
				// descriptors, but no character versions exists, so throw an
				// exception for the moment..
				throw new IllegalArgumentException();
			}

			if (stop)
				break;
		}

		QueryMessage msg = new QueryMessage();
		msg.setVersions(versionList);
		return msg;
	}
}
