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
	 * Maximum sizes for each fragment. The final size in the array will be used
	 * for all subsequent fragments too. Hence, only 1 size means that it will
	 * be used for all fragments.
	 */
	// FIXME force at least 1 size or some other measure?
	public final int[] maxFragmentSizes;
	
	/**
	 * Constructor.
	 *
	 * @param maxFragmentsAllowed Maximum fragments allowed.
	 * @param maxFragmentSizes Maximum fragment sizes allowed.
	 */
	public FragmenterInstructions(int maxFragmentsAllowed, int[] maxFragmentSizes) {
		this.maxFragmentsAllowed = maxFragmentsAllowed;
		this.maxFragmentSizes = maxFragmentSizes;
	}
}
