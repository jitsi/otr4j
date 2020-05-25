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
 * @author George Politis
 */
public enum SessionStatus {

	/**
	 * This state indicates that outgoing messages are sent without encryption.
	 * This is the state that is used before an OTR conversation is initiated. This
	 * is the initial state, and the only way to subsequently enter this state is
	 * for the user to explicitly request to do so via some UI operation.
	 */
	PLAINTEXT,

	/**
	 * This state indicates that outgoing messages are sent encrypted. This is
	 * the state that is used during an OTR conversation. The only way to enter
	 * this state is for the authentication state machine to successfully
	 * complete.
	 */
	ENCRYPTED,

	/**
	 * This state indicates that outgoing messages are not delivered at all.
	 * This state is entered only when the other party indicates he has terminated
	 * his side of the OTR conversation.
	 */
	FINISHED
}
