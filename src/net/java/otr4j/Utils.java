package net.java.otr4j;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Random;

public final class Utils {

    public static Boolean IsNullOrEmpty(String s){
        return s == null || s.length() < 1;
    }

	private static String byteToHex(byte b) {
		return "0x" + Integer.toString((b & 0xff) + 0x100, 16).substring(1);
	}

	private static String subString(Object o, int length) {
		if (o == null)
			throw new IllegalArgumentException();

		String s = o.toString();
		if (s.length() > length) {
			s = s.substring(0, length) + "...";
		}
		return s;
	}

	public static String dump(Object o) {
		return dump(o, true, 5);
	}

	/**
	 * 
	 * @param o
	 *            The object to dump.
	 * @param root
	 *            If true, it will print the class simple name of the object.
	 * @param maxLength
	 *            Field value maximum printable characters.
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static String dump(Object o, Boolean root, int maxLength) {
		if (o == null)
			return "";

		// TODO See "switch by class type" at
		// http://chaoticjava.com/posts/switch-by-class-type/
		StringBuffer buffer = new StringBuffer();
		Class oClass = o.getClass();
		if (root)
			buffer.append(oClass.getSimpleName() + " ");

		if (oClass.isArray()) {
			buffer.append("[");

			int length = Array.getLength(o);
			Boolean trimmed = false;
			if (length > maxLength) {
				trimmed = true;
				length = maxLength;
			}

			for (int i = 0; i < length; i++) {
				if (i > 0)
					buffer.append(",");

				Object value = Array.get(o, i);

				Class vClass = value.getClass();
				if (vClass.isArray())
					buffer.append(dump(value, false, maxLength));
				else if (vClass == Byte.class)
					buffer.append(byteToHex((Byte) value));
				else if (vClass == Boolean.class)
					buffer.append((Boolean) value);
				else
					buffer.append(subString(value, maxLength));
			}

			if (trimmed)
				buffer.append(",...");

			buffer.append("]");
		} else {
			buffer.append("{ ");

			StringBuffer objectBuffer = new StringBuffer();
			while (oClass != null) {
				Field[] fields = oClass.getDeclaredFields();
				for (int i = 0; i < fields.length; i++) {
					// Fields from superclasses are included, so checking for
					// i > 0 is not enough.

					Field field = fields[i];
					// Skip static fields, they don't describe out instance.
					if (Modifier.isStatic(field.getModifiers()))
						continue;

					if (objectBuffer.length() > 0)
						objectBuffer.append(", ");
					field.setAccessible(true);
					objectBuffer.append(field.getName());
					objectBuffer.append("=");
					try {
						Object value = field.get(o);
						if (value != null) {
							Class vClass = value.getClass();
							if (vClass.isArray())
								objectBuffer.append(dump(value, false,
										maxLength));
							else if (vClass == Byte.class)
								objectBuffer.append(byteToHex((Byte) value));
							else if (vClass == Boolean.class) {
								objectBuffer.append((Boolean) value);
							} else
								objectBuffer
										.append(subString(value, maxLength));
						}
					} catch (IllegalAccessException e) {
					}
				}
				oClass = oClass.getSuperclass();
			}

			buffer.append(objectBuffer);
			buffer.append(" }");
		}
		return buffer.toString();
	}

	public static byte[] intToByteArray(int value, int length) {
		byte[] b = new byte[length];
		for (int i = 0; i < length; i++) {
			int offset = (b.length - 1 - i) * 8;
			b[i] = (byte) ((value >>> offset) & 0xFF);
		}
		return b;
	}

	public static int byteArrayToInt(byte[] b) {
		int value = 0;
		for (int i = 0; i < b.length; i++) {
			int shift = (b.length - 1 - i) * 8;
			value += (b[i] & 0x000000FF) << shift;
		}
		return value;
	}

	public static byte[] trim(byte[] b) {
		// find leading zero count
		int i = 0;
		while ((int) b[i] == 0)
			i++;
	
		// remove leading 0's
		byte[] tmp = new byte[b.length - i];
		for (int j = 0; j < tmp.length; j++)
			tmp[j] = b[j + i];
	
		return tmp;
	}

	public static byte[] getRandomBytes(int length) {
		byte[] b = new byte[length];
		Random rnd = new Random();
		rnd.nextBytes(b);
		return b;
	}
}
