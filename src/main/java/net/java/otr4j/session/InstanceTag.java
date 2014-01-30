package net.java.otr4j.session;

import java.util.Random;

public class InstanceTag {

	private static final Random r = new Random();

	public static final int ZERO_VALUE = 0;

	public static final int SMALLEST_VALUE = 0x00000100;

	public static final int HIGHEST_VALUE = 0x11111111;

	public static final InstanceTag ZERO_TAG = new InstanceTag(0);

	public static final InstanceTag SMALLEST_TAG = new InstanceTag(0x00000100);

	public static final InstanceTag HIGHEST_TAG = new InstanceTag(0x11111111);

	private final int value;

	public static boolean isValidInstanceTag(int tagValue) {
		return 	tagValue == 0 ||
				(tagValue >= SMALLEST_VALUE && tagValue <= HIGHEST_VALUE);
	}

	public InstanceTag() {
		value = r.nextInt(HIGHEST_VALUE - SMALLEST_VALUE) + SMALLEST_VALUE;
	}

	public int getValue() {
		return value;
	}

	InstanceTag(int value)
	{
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
