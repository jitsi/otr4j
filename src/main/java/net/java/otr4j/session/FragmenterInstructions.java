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
	 * @param maxFragmentsAllowed
	 *            Maximum fragments allowed.
	 * @param maxFragmentSize
	 *            Maximum fragment size allowed.
	 */
	public FragmenterInstructions(int maxFragmentsAllowed, int maxFragmentSize) {
		this.maxFragmentsAllowed = maxFragmentsAllowed;
		this.maxFragmentSize = maxFragmentSize;
	}

	/**
	 * Verify instructions for safe usage. It will also create a default
	 * instructions instance in case null is provided.
	 * 
	 * If an invalid number is specified, it will be replaced with UNLIMITED.
	 * 
	 * @param instructions
	 *            the instructions or null for defaults
	 * @return returns instructions
	 */
	static FragmenterInstructions verify(FragmenterInstructions instructions) {
		if (instructions == null) {
			return new FragmenterInstructions(UNLIMITED, UNLIMITED);
		}
		if (instructions.maxFragmentsAllowed != UNLIMITED
				&& instructions.maxFragmentsAllowed < 0) {
			throw new IllegalArgumentException(
					"Invalid fragmenter instructions: bad number of fragments.");
		}
		if (instructions.maxFragmentSize != UNLIMITED
				&& instructions.maxFragmentSize < 0) {
			throw new IllegalArgumentException(
					"Invalid fragmenter instructions: bad fragment size.");
		}
		return instructions;
	}
}
