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
package net.java.otr4j;

import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;

/**
 *
 * @author George Politis
 */
public interface OtrSessionManager {

	/**
     * Get an OTR session.
     * @param sessionID the session to retrieve
     * @return MVN_PASS_JAVADOC_INSPECTION
     */
	Session getSession(SessionID sessionID);

	void addOtrEngineListener(OtrEngineListener l);

	void removeOtrEngineListener(OtrEngineListener l);
}
