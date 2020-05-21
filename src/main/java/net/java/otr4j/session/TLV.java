package net.java.otr4j.session;

/**
 * Type/Length/Value record.
 * - Type (SHORT): The type of this record. Records with unrecognized types should be ignored.
 * - Length (SHORT): The length of the following field
 * - Value (BYTEs): Any pertinent data for the record type
 * A list of these might be attached to data-messages.
 */
public class TLV {

	/** This is just padding for the encrypted message, and should be ignored. */
	public static final int PADDING = 0;
	/** The sender has thrown away his OTR session keys with you */
	public static final int DISCONNECTED = 0x0001;

	/* The message contains a step in the Socialist Millionaire's Protocol. */
	public static final int SMP1 = 0x0002;
	public static final int SMP2 = 0x0003;
	public static final int SMP3 = 0x0004;
	public static final int SMP4 = 0x0005;
	public static final int SMP_ABORT = 0x0006;
	/** Like {@link #SMP1}, but there's a question for the buddy at the beginning. */
	public static final int SMP1Q = 0x0007;

	int type;
	byte[] value;

	public TLV(int type, byte[] value) {
		this.setType(type);
		this.setValue(value);
	}

	public void setType(int type) {
		this.type = type;
	}

	public int getType() {
		return type;
	}

	public void setValue(byte[] value) {
		this.value = value;
	}

	public byte[] getValue() {
		return value;
	}
}
