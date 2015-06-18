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

import java.security.PublicKey;
import java.util.List;

import net.java.otr4j.session.InstanceTag;
import net.java.otr4j.session.Session;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;
import net.java.otr4j.session.TLV;

/**
 * 
 * @author George Politis
 * 
 */
public interface OtrSessionManager {

	/**
     * Get an OTR session.
     * @return MVN_PASS_JAVADOC_INSPECTION
     */
	public abstract Session getSession(SessionID sessionID);

	public abstract void addOtrEngineListener(OtrEngineListener l);

	public abstract void removeOtrEngineListener(OtrEngineListener l);
}
