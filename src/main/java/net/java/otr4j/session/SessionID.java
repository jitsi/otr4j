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
package net.java.otr4j.session;

/**
 *
 * @author George Politis
 */
public final class SessionID {

	public SessionID(String accountID, String userID, String protocolName) {
		this.accountID = accountID;
		this.userID = userID;
		this.protocolName = protocolName;
	}

	private final String accountID;
	private final String userID;
	private final String protocolName;

	public static final SessionID EMPTY = new SessionID(null, null, null);
	/** @deprecated use {@link #EMPTY} instead */
	public static final SessionID Empty = EMPTY;

	public String getAccountID() {
		return accountID;
	}

	public String getUserID() {
		return userID;
	}

	public String getProtocolName() {
		return protocolName;
	}

	@Override
	public String toString() {
		return accountID + '_' + protocolName + '_' + userID;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((accountID == null) ? 0 : accountID.hashCode());
		result = prime * result
				+ ((protocolName == null) ? 0 : protocolName.hashCode());
		result = prime * result + ((userID == null) ? 0 : userID.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SessionID other = (SessionID) obj;
		if (accountID == null) {
			if (other.accountID != null)
				return false;
		} else if (!accountID.equals(other.accountID))
			return false;
		if (protocolName == null) {
			if (other.protocolName != null)
				return false;
		} else if (!protocolName.equals(other.protocolName))
			return false;
		if (userID == null) {
			if (other.userID != null)
				return false;
		} else if (!userID.equals(other.userID))
			return false;
		return true;
	}
}
