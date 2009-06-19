package net.java.otr4j.utils;

import java.lang.reflect.Field;

import net.java.otr4j.message.MessageType;
import junit.framework.TestCase;

public class UtilsTest extends TestCase {
	public void testIntToByteArray() {
		Field[] fields = MessageType.class.getDeclaredFields();
		for (Field field : fields) {
			try {
				int x = field.getInt(null);
				byte[] xb = Utils.intToByteArray(x, 4);
				int xfromb = Utils.byteArrayToInt(xb);
				assertEquals(x, xfromb);
			} catch (Exception e) {
				continue;
			}
		}
	}
}
