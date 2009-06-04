package net.java.otr4j.message.encoded;

import junit.framework.TestCase;

import org.junit.Test;

import net.java.otr4j.message.encoded.DataMessage;

public class DataMessageTest extends TestCase {
	private static String DataMessage1 = "?OTR:AAIDAAAAAAEAAAABAAAAwCcGDemZNMCfOZl4ACf8L2G2G2qXDX6gJxKXBEgOjA7U/lgQJ+UklQzp0txnWqAhQ8HDfmGoMeo5Ez0N8X1xlXq8f3UL/fPrp7X2JW9JHr2fi541oPmtJpLtbSlIA+ri8Y1ptoxTriIyMWsngvSAkwFWb7lcDyJwXsc3ZUVi2xG/6ggdU+XxZe7ow5KfTK0usMIBnAGOfpygel6UBk7UPGRd9rWFaq1JOqkFopcKhar4IMydeaJa3AFbfrrmSYqqowAAAAAAAAABAAAABkOjnTF/CcaT9PEoW1n+hukkVE+RtvCNpSn4AAAAAA==.";

	// From OTR page.
	private static String DataMessage2 = "?OTR:AAEDAAAAAQAAAAEAAADAVf3Ei72ZgFeKqWvLMnuVPVCwxktsOZ1QdjeLp6jn62mCVtlY9nS6sRkecpjuLYHRxyTdRu2iEVtSsjZqK55ovZ35SfkOPHeFYa9BIuxWi9djHMVKQ8KOVGAVLibjZ6P8LreDSKtWDv9YQjIEnkwFVGCPfpBq2SX4VTQfJAQXHggR8izKxPvluXUdG9rIPh4cac98++VLdIuFMiEXjUIoTX2rEzunaCLMy0VIfowlRsgsKGrwhCCv7hBWyglbzwz+AAAAAAAAAAQAAAF2SOrJvPUerB9mtf4bqQDFthfoz/XepysnYuReHHEXKe+BFkaEoMNGiBl4TCLZx72DvmZwKCewWRH1+W66ggrXKw2VdVl+vLsmzxNyWChGLfBTL5/3SUF09BfmCEl03Ckk7htAgyAQcBf90RJznZndv7HwVAi3syupi0sQDdOKNPyObR5FRtqyqudttWmSdmGCGFcZ/fZqxQNsHB8QuYaBiGL7CDusES+wwfn8Q7BGtoJzOPDDx6KyIyox/flPx2DZDJIZrMz9b0V70a9kqKLo/wcGhvHO6coCyMxenBAacLJ1DiINLKoYOoJTM7zcxsGnvCxaDZCvsmjx3j8Yc5r3i3ylllCQH2/lpr/xCvXFarGtG7+wts+UqstS9SThLBQ9Ojq4oPsX7HBHKvq19XU3/ChIgWMy+bczc5gpkC/eLAIGfJ0D5DJsl68vMXSmCoFK0HTwzzNa7lnZK4IutYPBNBCv0pWORQqDpskEz96YOGyB8+gtpFgCrkuV1bSB9SRVmEBfDtKPQFhKowAAAAA=.";

	@Test
	public void testCreate() {
		// TODO Implement
	}

	@Test
	public void testDisassemble() {
		DataMessage dataMessage1 = DataMessage.disassemble(DataMessage1);
		assertNotNull(dataMessage1);
		
		DataMessage dataMessage2 = DataMessage.disassemble(DataMessage2);
		assertNotNull(dataMessage2);
	}
}
