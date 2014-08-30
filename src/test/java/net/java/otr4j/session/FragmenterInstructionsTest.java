package net.java.otr4j.session;

import org.junit.*;

public class FragmenterInstructionsTest {

	@Test
	public void testConstruction() {
		FragmenterInstructions instructions = new FragmenterInstructions(1, new int[] {100});
		Assert.assertEquals(1, instructions.maxFragmentsAllowed);
		Assert.assertArrayEquals(new int[] {100}, instructions.maxFragmentSizes);
	}
}
