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

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author Danny van Heumen
 */
public class SerializationUtilsTest {

	@Test
	public void testOTRQueryMessageV1NotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTR? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV2NotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTRv2? some other content ..."));
	}
	
	@Test
	public void testOTRQueryMessageV23NotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTRv23? some other content ..."));
	}
	
	@Test
	public void testCorrectOTREncodingDetection() {
		Assert.assertTrue(SerializationUtils.otrEncoded("?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8vjPEWAJ6gBXvZrY6ZQrx3gb4v0UaSMOMiR5sB7Eaulb2Yc6RmRnnlxgUUC2alosg4WIeFN951PLjScajVba6dqlDi+q1H5tPvI5SWMN7PCBWIJ41+WvF+5IAZzQZYgNaVLbAAAAAAAAAAEAAAAHwNiIi5Ms+4PsY/L2ipkTtquknfx6HodLvk3RAAAAAA==."));
	}

	@Test
	public void testOTRv2FragmentNotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTR,1,3,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}

	@Test
	public void testOTRv3FragmentNotOTREncoded() {
		Assert.assertFalse(SerializationUtils.otrEncoded("?OTR|5a73a599|27e31597,00001,00003,?OTR:AAMDJ+MVmSfjFZcAAAAAAQAAAAIAAADA1g5IjD1ZGLDVQEyCgCyn9hbrL3KAbGDdzE2ZkMyTKl7XfkSxh8YJnudstiB74i4BzT0W2haClg6dMary/jo9sMudwmUdlnKpIGEKXWdvJKT+hQ26h9nzMgEditLB8v,"));
	}
}
