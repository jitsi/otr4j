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
package net.java.otr4j.io;

/**
 *
 * @author George Politis
 */
public interface SerializationConstants {

	String HEAD = "?OTR";
	char HEAD_ENCODED = ':';
	char HEAD_ERROR = ' ';
	char HEAD_QUERY_Q = '?';
	char HEAD_QUERY_V = 'v';
	String ERROR_PREFIX = "Error:";

	int TYPE_LEN_BYTE = 1;
	int TYPE_LEN_SHORT = 2;
	int TYPE_LEN_INT = 4;
	int TYPE_LEN_MAC = 20;
	int TYPE_LEN_CTR = 8;

	int DATA_LEN = TYPE_LEN_INT;
	int TLV_LEN = TYPE_LEN_SHORT;
}
