package net.java.otr4j.session;

import java.util.Random;

public class InstanceTag {

	private static final Random r = new Random();

	public static final int ZERO_VALUE = 0;

	public static final int SMALLEST_VALUE = 0x00000100;

	public static final int HIGHEST_VALUE = 0xffffffff;

	public static final InstanceTag ZERO_TAG = new InstanceTag(ZERO_VALUE);

	public static final InstanceTag SMALLEST_TAG = new InstanceTag(SMALLEST_VALUE);

	public static final InstanceTag HIGHEST_TAG = new InstanceTag(HIGHEST_VALUE);

	/**
	 * Range for valid instance tag values.
	 * Corrected for existence of smallest value boundary.
	 */
	private static final long RANGE = 0xfffffeffL;

	/**
	 * Value of the instance tag instance.
	 */
	private final int value;

	public static boolean isValidInstanceTag(final int tagValue) {
		return !(0 < tagValue && tagValue < SMALLEST_VALUE);
	}

	public InstanceTag() {
		final long val = (long)(r.nextDouble()*RANGE) + SMALLEST_VALUE;
		// Because 0xffffffff is the maximum value for both the tag and
		// the 32 bit integer range, we are able to cast to int without
		// loss. The (decimal) interpretation changes, though, because
		// Java's int interprets the last bit as the sign bit. This does
		// not matter, however, since we do not need to do value
		// comparisons / ordering. We only care about equal/not equal.
		this.value = (int)val;
	}

	public int getValue() {
		return value;
	}

	InstanceTag(final int value) {
		if (!isValidInstanceTag(value))
		{
			throw new IllegalArgumentException("Invalid tag value.");
		}
		this.value = value;
	}

	public boolean equals(Object other) {
		if (this == other)
			return true;
		if (!(other instanceof InstanceTag))
			return false;

		InstanceTag otherInstanceTag = (InstanceTag) other;

		return this.value == otherInstanceTag.getValue();
	}

	public int hashCode() {
		return value;
	}
}
