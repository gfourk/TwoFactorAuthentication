package utils;

import static org.junit.Assert.*;

import org.junit.Test;

public class utilsTest {

	@Test
	public void testToHexByteArrayInt() {
		String s = "lala";
		String hexstr = utils.toHex(s.getBytes());
		System.out.println("hex str from string bytes " + hexstr);
		byte[] fromhex = utils.toByte(hexstr);
		String res = new String(fromhex);
		System.out.println("result string from hex: " + res);
		assertTrue(res.equals(s));
	}

	@Test
	public void testToHexByteArray() {
		String s = "lala";
		String hexstr = utils.toHex(s.getBytes());
		System.out.println("hex str from string bytes " + hexstr);
		byte[] fromhex = utils.toByte(hexstr);
		String res = new String(fromhex);
		System.out.println("result string from hex: " + res);
		assertTrue(res.equals(s));
	}

	@Test
	public void testToByte() {
		String s = "lala";
		byte[] in = s.getBytes();
		String hexstr = utils.toHex(in);
		System.out.println("hex str from string bytes " + hexstr);
		byte[] fromhex = utils.toByte(hexstr);
		String res = new String(fromhex);
		System.out.println("result string from hex: " + res);
		assertTrue(res.equals(s));
	}

	@Test
	public void testCopy() {
		String s = "lala";
		byte[] in = s.getBytes();

		assertTrue(utils.compare(in, utils.copy(in)));
	}

	@Test
	public void testConcat() {
		String s = "first";
		String t = "second";
		byte[] concat = utils.concat(s.getBytes(), t.getBytes());
		assertTrue(new String(concat).equals(s + t));
	}

	@Test
	public void testCompare() {
		String s = "lala";
		byte[] one = s.getBytes();
		String t = "lala";
		byte[] other = t.getBytes();

		System.out.println(utils.toHex(one));
		System.out.println(utils.toHex(other));

		System.out.println(utils.compare(one, other));

		assertTrue(utils.compare(one, other) == true);
	}

}
