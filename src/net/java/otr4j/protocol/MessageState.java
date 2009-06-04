package net.java.otr4j.protocol;

/**
 * The message state variable, msgstate, controls what happens to outgoing
 * messages typed by the user.
 * 
 * @author george
 * 
 */
public enum MessageState {
	/**
	 * This state indicates that outgoing messages are sent without encryption.
	 * This is the state that is used before an OTR conversation is initiated.
	 * This is the initial state, and the only way to subsequently enter this
	 * state is for the user to explicitly request to do so via some UI
	 * operation.
	 */
	PLAINTEXT,
	/**
	 * This state indicates that outgoing messages are sent encrypted. This is
	 * the state that is used during an OTR conversation. The only way to enter
	 * this state is for the authentication state machine (below) to
	 * successfully complete.
	 */
	ENCRYPTED,
	/**
	 * This state indicates that outgoing messages are not delivered at all.
	 * This state is entered only when the other party indicates he has
	 * terminated his side of the OTR conversation. For example, if Alice and
	 * Bob are having an OTR conversation, and Bob instructs his OTR client to
	 * end its private session with Alice (for example, by logging out), Alice
	 * will be notified of this, and her client will switch to MSGSTATE_FINISHED
	 * mode. This prevents Alice from accidentally sending a message to Bob in
	 * plaintext. (Consider what happens if Alice was in the middle of typing a
	 * private message to Bob when he suddenly logs out, just as Alice hits
	 * Enter.)
	 */
	FINISHED
}
