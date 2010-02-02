package net.java.otr4j.io;

import java.io.FilterReader;
import java.io.IOException;
import java.io.Reader;
import java.util.List;
import java.util.Vector;

import net.java.otr4j.io.messages.QueryMessage;
import net.java.otr4j.io.messages.SerializationConstants;

public class OtrQueryReader extends FilterReader {

	public OtrQueryReader(Reader in, boolean v2Mode) {
		super(in);
		this.v2Mode = v2Mode;
	}

	private boolean v2Mode;
	private boolean finished = false;
	private boolean isFirstRead = true;

	public QueryMessage readMessage() throws IOException {

		List<Integer> versions = new Vector<Integer>();

		int i;
		while ((i = readVersion()) > -1) {
			if (i > 0 && !versions.contains(i))
				versions.add(i);
		}

		QueryMessage qmsg = new QueryMessage(versions);
		return qmsg;
	}

	private final String headQueryV = new String(
			SerializationConstants.HEAD_QUERY_V);

	public int readVersion() throws IOException {
		if (finished)
			return -1;

		int i = in.read();
		if (i < 0)
			return i;

		String s = String.valueOf((char) i);
		if (v2Mode) {
			if (s.equals("?")) {
				// final ? is found, stop reading version numbers.
				finished = true;
				return -1;
			}

			return Integer.parseInt(s);
		} else {
			if (isFirstRead) {
				isFirstRead = false;
				if (!s.equalsIgnoreCase(headQueryV)) {
					// ? is not followed by a v, no version numbers are
					// expected.
					this.finished = true;
					return -1;
				}
			}

			if (s.equals("?")) {
				// final ? is found, stop reading version numbers.
				finished = true;
				return -1;
			} else
				return Integer.decode(s);
		}
	}
}