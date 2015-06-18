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
package net.java.otr4j;

/**
 * 
 * @author George Politis
 * 
 */
public interface OtrPolicy {

	public static final int ALLOW_V1 = 0x01;
	public static final int ALLOW_V2 = 0x02;
	public static final int ALLOW_V3 = 0x40; // ALLOW_V3 is set to 0x40 for compatibility with older versions
	public static final int REQUIRE_ENCRYPTION = 0x04;
	public static final int SEND_WHITESPACE_TAG = 0x8;
	public static final int WHITESPACE_START_AKE = 0x10;
	public static final int ERROR_START_AKE = 0x20;
	public static final int VERSION_MASK = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3);

	// The four old version 1 policies correspond to the following combinations
	// of flags (adding an allowance for version 2 of the protocol):

	public static final int NEVER = 0x00;
	public static final int OPPORTUNISTIC = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3
			| SEND_WHITESPACE_TAG | WHITESPACE_START_AKE | ERROR_START_AKE);
	public static final int OTRL_POLICY_MANUAL = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3);
	public static final int OTRL_POLICY_ALWAYS = (ALLOW_V1 | ALLOW_V2 | ALLOW_V3
			| REQUIRE_ENCRYPTION | WHITESPACE_START_AKE | ERROR_START_AKE);
	public static final int OTRL_POLICY_DEFAULT = OPPORTUNISTIC;

	public abstract boolean getAllowV1();

	public abstract boolean getAllowV2();

	public abstract boolean getAllowV3();

	public abstract boolean getRequireEncryption();

	public abstract boolean getSendWhitespaceTag();

	public abstract boolean getWhitespaceStartAKE();

	public abstract boolean getErrorStartAKE();

	public abstract int getPolicy();

	public abstract void setAllowV1(boolean value);

	public abstract void setAllowV2(boolean value);

	public abstract void setAllowV3(boolean value);

	public abstract void setRequireEncryption(boolean value);

	public abstract void setSendWhitespaceTag(boolean value);

	public abstract void setWhitespaceStartAKE(boolean value);

	public abstract void setErrorStartAKE(boolean value);

	public abstract void setEnableAlways(boolean value);

	public abstract boolean getEnableAlways();

	public abstract void setEnableManual(boolean value);

	public abstract boolean getEnableManual();
}
