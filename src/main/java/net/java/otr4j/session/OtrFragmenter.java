package net.java.otr4j.session;

import java.io.IOException;
import java.util.LinkedList;

import net.java.otr4j.OtrPolicy;

/**
 * OTR fragmenter.
 * 
 * TODO It may be better to separate the v2 and v3 implementations into
 * specialized classes.
 *
 * @author Danny van Heumen
 */
public class OtrFragmenter {
	/**
	 * Exception message in cases where only OTRv1 is allowed.
	 */
	private static final String OTRv1_NOT_SUPPORTED = "Fragmentation is not supported in OTRv1.";

	/**
	 * The maximum number of fragments supported by the OTR (v3) protocol.
	 */
	private static final int MAXIMUM_NUMBER_OF_FRAGMENTS = 65535;

	/**
	 * The message format of an OTRv3 message fragment.
	 */
	private static final String OTRv3_MESSAGE_FRAGMENT_FORMAT = "?OTR|%x|%x,%05d,%05d,%s,";

	/**
	 * The message format of an OTRv2 message fragment.
	 */
	private static final String OTRv2_MESSAGE_FRAGMENT_FORMAT = "?OTR,%d,%d,%s,";

	/**
	 * Session instance.
	 */
	private final Session session;

	/**
	 * Instructions on how to fragment the input message.
	 */
	private final FragmenterInstructions instructions;

	/**
	 * Constructor.
	 * 
	 * @param session session instance (cannot be null)
	 * @param instructions fragmenter instructions (cannot be null)
	 */
	public OtrFragmenter(final Session session, final FragmenterInstructions instructions) {
		if (session == null) {
			throw new NullPointerException("session cannot be null");
		}
		this.session = session;
		if (instructions == null) {
			this.instructions = new FragmenterInstructions(
					FragmenterInstructions.UNLIMITED,
					new int[] { FragmenterInstructions.UNLIMITED });
		} else {
			this.instructions = instructions;
		}
	}
	
	/**
	 * Get instructions for fragmentation behaviour.
	 *
	 * @return returns instructions
	 */
	public FragmenterInstructions getInstructions() {
		return this.instructions;
	}

	/**
	 * Calculate the number of fragments that are required for the message to be
	 * sent fragmented completely.
	 *
	 * @param message
	 *            the original message
	 * @return returns the number of fragments required
	 * @throws IOException
	 *             throws an IOException in case fragment size is too small to
	 *             store any content or when the provided policy does not
	 *             support fragmentation, for example if only OTRv1 is allowed.
	 */
	public int numberOfFragments(final String message) throws IOException {
		if (this.instructions.maxFragmentSizes[0] == FragmenterInstructions.UNLIMITED
				|| this.instructions.maxFragmentSizes[0] >= message.length()) {
			return 1;
		}
		return computeFragmentNumber(message);
	}

	/**
	 * Compute the number of fragments required.
	 *
	 * @param message the original message
	 * @return returns number of fragments required.
	 * @throws IOException throws an IOException if fragment size is too small.
	 */
	private int computeFragmentNumber(final String message) throws IOException {
		int messages = 0;
		int remaining = message.length();
		for (int index = 0; remaining > 0; index = nextSizeIndex(index)) {
			final int overhead = computeHeaderSize();
			final int contentSize = instructions.maxFragmentSizes[index] - overhead;
			if (contentSize <= 0) {
				throw new IOException("Fragment size too small for storing content.");
			}
			remaining -= contentSize;
			messages++;
		}
		return messages;
	}

	/**
	 * Fragment the given message into pieces as specified by the
	 * FragmenterInstructions instance.
	 * 
	 * @param message
	 *            the original message
	 * @return returns an array of message fragments
	 * @throws IOException
	 *             throws an IOException if the fragment size is too small or if
	 *             the maximum number of fragments is exceeded.
	 */
	public String[] fragment(final String message) throws IOException {
		if (instructions.maxFragmentSizes[0] == FragmenterInstructions.UNLIMITED
				|| instructions.maxFragmentSizes[0] >= message.length()) {
			return new String[] { message };
		}
		final int num = numberOfFragments(message);
		if (instructions.maxFragmentsAllowed > FragmenterInstructions.UNLIMITED
				&& instructions.maxFragmentsAllowed < num) {
			throw new IOException("Need more fragments to store full message.");
		}
		if (num > MAXIMUM_NUMBER_OF_FRAGMENTS) {
			throw new IOException(
					"Number of necessary fragments exceeds limit.");
		}
		int start = 0;
		int idx = 0;
		final LinkedList<String> fragments = new LinkedList<String>();
		while (start < message.length()) {
			final int size = instructions.maxFragmentSizes[idx]
					- computeHeaderSize();
			// Either get new position or position of exact message end
			final int end = Math.min(start + size, message.length());

			final String partialContent = message.substring(start, end);
			fragments.add(createMessageFragment(fragments.size(), num,
					partialContent));

			// increase index for next fragment size
			idx = nextSizeIndex(idx);
			start = end;
		}
		return fragments.toArray(new String[fragments.size()]);
	}

	/**
	 * Create a message fragment.
	 *
	 * @param count
	 *            the current fragment number
	 * @param total
	 *            the total number of fragments
	 * @param partialContent
	 *            the content for this fragment
	 * @return returns the full message fragment
	 * @throws UnsupportedOperationException
	 *             in case v1 is only allowed in policy
	 */
	private String createMessageFragment(final int count, final int total,
			final String partialContent) {
		if (getPolicy().getAllowV3()) {
			return createV3MessageFragment(count, total, partialContent);
		} else if (getPolicy().getAllowV2()) {
			return createV2MessageFragment(count, total, partialContent);
		} else {
			throw new UnsupportedOperationException(OTRv1_NOT_SUPPORTED);
		}
	}

	/**
	 * Create a message fragment according to the v3 message format.
	 *
	 * @param count the current fragment number
	 * @param total the total number of fragments
	 * @param partialContent the content for this fragment
	 * @return returns the full message fragment
	 */
	private String createV3MessageFragment(final int count, final int total, final String partialContent) {
		final String msg = String.format(OTRv3_MESSAGE_FRAGMENT_FORMAT,
				getSenderInstance(), getReceiverInstance(), count + 1, total, partialContent);
		return msg;
	}

	/**
	 * Create a message fragment according to the v2 message format.
	 *
	 * @param count the current fragment number
	 * @param total the total number of fragments
	 * @param partialContent the content for this fragment
	 * @return returns the full message fragment
	 */
	private String createV2MessageFragment(final int count, final int total,
			final String partialContent) {
		final String msg = String.format(OTRv2_MESSAGE_FRAGMENT_FORMAT,
				count + 1, total, partialContent);
		return msg;
	}

	/**
	 * Compute size of fragmentation header size.
	 *
	 * @return returns size of fragment header
	 * @throws UnsupportedOperationException
	 *             in case v1 is only allowed in policy
	 */
	private int computeHeaderSize() {
		if (getPolicy().getAllowV3()) {
			return computeHeaderV3Size();
		} else if (getPolicy().getAllowV2()) {
			return computeHeaderV2Size();
		} else {
			throw new UnsupportedOperationException(OTRv1_NOT_SUPPORTED);
		}
	}

	/**
	 * Compute the overhead size for a v3 header.
	 *
	 * @return returns size of v3 header
	 */
	private int computeHeaderV3Size() {
		// For a OTRv3 header this seems to be a constant number, since the
		// specs seem to suggest that smaller numbers have leading zeros.
		return 36;
	}

	/**
	 * Compute the overhead size for a v2 header.
	 *
	 * Current implementation returns an upper bound size for the size of the
	 * header. As I understand it, the protocol does not require leading zeros
	 * to fill a 5-space number are so in theory it is possible to gain a few
	 * extra characters per message if an exact calculation of the number of
	 * required chars is used.
	 *
	 * TODO I think this is dependent on the number of chars in a decimal
	 * representation of the current and total number of fragments.
	 *
	 * @return returns size of v2 header
	 */
	private int computeHeaderV2Size() {
		// currently returns an upper bound (for the case of 10000+ fragments)
		return 18;
	}

	/**
	 * Get next size index. This method implements the logic for iterating
	 * through available sizes and infinitely repeating the last available
	 * fragment size.
	 *
	 * @param current the current size index
	 * @return returns the next size index
	 */
	private int nextSizeIndex(int current) {
		if (current + 1 < this.instructions.maxFragmentSizes.length) {
			return current + 1;
		}
		return current;
	}
	
	private OtrPolicy getPolicy() {
		return this.session.getSessionPolicy();
	}
	
	private int getSenderInstance() {
		return this.session.getSenderInstanceTag().getValue();
	}
	
	private int getReceiverInstance() {
		return this.session.getReceiverInstanceTag().getValue();
	}
}
