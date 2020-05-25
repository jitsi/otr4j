/*
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.java.otr4j.io.messages;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 *
 * @author George Politis
 */
public class QueryMessage extends AbstractMessage {

	public List<Integer> versions;

	protected QueryMessage(int messageType, List<Integer> versions) {
		super(messageType);
		this.versions = (versions == null) ? versions
				: Collections.unmodifiableList(
						new ArrayList<Integer>(versions));
	}

	public QueryMessage(List<Integer> versions) {
		this(MESSAGE_QUERY, versions);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result
				+ ((versions == null) ? 0 : versions.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		QueryMessage other = (QueryMessage) obj;
		if (versions == null) {
			if (other.versions != null)
				return false;
		} else if (!versions.equals(other.versions))
			return false;
		return true;
	}
}
