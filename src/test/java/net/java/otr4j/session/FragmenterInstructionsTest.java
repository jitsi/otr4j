/*
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.java.otr4j.session;

import org.junit.Assert;
import org.junit.Test;

/**
 * Fragmenter Instructions tests.
 *
 * @author Danny van Heumen
 */
public class FragmenterInstructionsTest {

	@Test
	public void testConstruction() {
		FragmenterInstructions instructions = new FragmenterInstructions(1, 100);
		Assert.assertEquals(1, instructions.maxFragmentsAllowed);
		Assert.assertEquals(100, instructions.maxFragmentSize);
	}
	
	@Test
	public void testVerifyNullInstructions() {
		FragmenterInstructions instructions = FragmenterInstructions.verify(null);
		Assert.assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentsAllowed);
		Assert.assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentSize);
	}
	
	@Test
	public void testVerifyCorrectInstructionsUnlimited() {
		FragmenterInstructions instructions = FragmenterInstructions.verify(new FragmenterInstructions(FragmenterInstructions.UNLIMITED, FragmenterInstructions.UNLIMITED));
		Assert.assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentsAllowed);
		Assert.assertEquals(FragmenterInstructions.UNLIMITED, instructions.maxFragmentSize);
	}
	
	@Test
	public void testVerifyCorrectInstructionsPositiveValues() {
		FragmenterInstructions instructions = FragmenterInstructions.verify(new FragmenterInstructions(4, 210));
		Assert.assertEquals(4, instructions.maxFragmentsAllowed);
		Assert.assertEquals(210, instructions.maxFragmentSize);
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testVerifyBadFragmentsNumber() {
		FragmenterInstructions.verify(new FragmenterInstructions(-4, 50));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testVerifyBadFragmentSize() {
		FragmenterInstructions.verify(new FragmenterInstructions(4, -50));
	}
	
	@Test(expected = IllegalArgumentException.class)
	public void testVerifyBadBoth() {
		FragmenterInstructions.verify(new FragmenterInstructions(-180, -50));
	}
}
