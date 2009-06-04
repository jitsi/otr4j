package net.java.otr4j.protocol;

/**
 * 
 * @author george
 *
 */
public enum AuthenticationState {
	/**
	 * This state indicates that the authentication protocol is not currently in
	 * progress. This is the initial state.
	 */
	NONE,
	/**
	 * After Bob initiates the authentication protocol by sending Alice the D-H
	 * Commit Message, he enters this state to await Alice's reply.
	 */
	AWAITING_DHKEY,
	/**
	 * After Alice receives Bob's D-H Commit Message, and replies with her own
	 * D-H Key Message, she enters this state to await Bob's reply.
	 */
	AWAITING_REVEALSIG,
	/**
	 * After Bob receives Alice's D-H Key Message, and replies with his own
	 * Reveal Signature Message, he enters this state to await Alice's reply.
	 */
	AWAITING_SIG,
	/**
	 * For OTR version 1 compatibility, if Bob sends a version 1 Key Exchange
	 * Message to Alice, he enters this state to await Alice's reply.
	 */
	V1_SETUP
}
