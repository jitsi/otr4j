package net.java.otr4j.session;

/**
 * Instructions for the fragmenter explaining how to fragment a payload.
 *
 * @author Danny van Heumen
 */
public class FragmenterInstructions {
	/**
	 * Constant for indicating an unlimited amount.
	 */
	public static final int UNLIMITED = -1;
	
	/**
	 * Maximum number of fragments.
	 */
	public final int maxFragmentsAllowed;
	
	/**
	 * Maximum size for fragments.
	 */
	public final int maxFragmentSize;
	
	/**
	 * Constructor.
	 *
	 * @param maxFragmentsAllowed Maximum fragments allowed.
	 * @param maxFragmentSize Maximum fragment size allowed.
	 */
	public FragmenterInstructions(int maxFragmentsAllowed, int maxFragmentSize) {
		this.maxFragmentsAllowed = maxFragmentsAllowed;
		this.maxFragmentSize = maxFragmentSize;
	}
}
