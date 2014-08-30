package net.java.otr4j.session;

public class FragmenterInstructions {
	public static final int UNLIMITED = -1;
	
	public final int maxFragmentsAllowed;
	// FIXME force at least 1 size or some other measure?
	public final int[] maxFragmentSizes;
	
	public FragmenterInstructions(int maxFragmentsAllowed, int[] maxFragmentSizes) {
		this.maxFragmentsAllowed = maxFragmentsAllowed;
		this.maxFragmentSizes = maxFragmentSizes;
	}
}
