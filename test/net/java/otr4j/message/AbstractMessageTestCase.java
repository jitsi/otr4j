package net.java.otr4j.message;

import junit.framework.TestCase;

abstract class AbstractMessageTestCase extends TestCase {
	public abstract void testRead() throws Exception;

	public abstract void testWrite() throws Exception;
}
