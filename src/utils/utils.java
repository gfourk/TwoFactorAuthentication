package utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class utils {
	
	
    private static String digits = "0123456789abcdef";

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data)
    {
    	if(data == null ) return null;
    	
        StringBuffer    buf = new StringBuffer();

        for (int i = 0; i != data.length; i++)
        {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }
    
    
    /**
     * Hex String to byte Array method
     * @param s the string to be converted to a byte array
     * @return a byte array or converted from a string or null
     * if given string was null or empty
     */
    public static byte[] toByte(String s) {
    	try{
    	// argument check
    	if(s == null) return null;
    	if(s.length() == 0) return null;
        
    	int len = s.length();
    	
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    	}
    	catch(Exception e){return null;}
    }
    /**
     * Copies a byte array
     * @param in the input byte array
     * @return a copy of the byte array given or null if input is null or zero length
     */
    public static byte[] copy(byte[] in){
    	// chekc arguments
    	if(in == null || in.length == 0) return null;
    	
    	byte[] out = new byte[in.length];
   
    	for(int i = 0; i < in.length; i++){
    		out[i] = in[i];
    	}
    	return out;
    }
    
    /**
     * Overloaded method for copying
     * copies the input string to the output form start index (inclusive)
     * and for length bytes
     * @param in
     * @param start
     * @param length
     * @return
     */
    public static byte[] copy(byte[] in,int start, int length){
    	// chekc arguments
    	if(in == null || in.length == 0) return null;
    	
    	// start must be 
    	if(start >= in.length || start < 0 || length <= 0) return null;
    	
    	// if the requested subarray exceeds the input array
    	// just return as much there is
    	if(in.length < start + length)
    		length = in.length - start;
    	
    	byte[] out = new byte[length];
   
    	for(int i = 0; i < length; i++){
    		out[i] = in[start+i];
    	}
    	return out;
    }
    
    /**
     * Concatenates two byte arrays in order
     * @param first the first byte array
     * @param second the second byte array 
     * @return a new byte array concatenation of the two, null if both  are null
     * or a copy of the one if the other is null
     */
    public static byte[] concat(byte[] first, byte[] second){
    	
    	// argument check
    	if(first == null && second == null ) return null;
    	
    	if(first == null) return utils.copy(second);
    	if(second == null) return utils.copy(first);
    	
    	// create a new byte array
    	byte[] out = new byte[first.length + second.length];
    	
    	for(int i = 0; i < first.length; i++)
    		out[i] = first[i];
    	
    	for(int i = 0; i < second.length; i++)
    		out[first.length + i] = second[i];
    	
    	return out;
    }
    
    /**
     * compares two bte arrays for equality
     * @param one 
     * @param other
     * @return true if both are not null and equal byte by byte
     */
    public static boolean compare(byte[] one, byte[] other){
    	
    	// if just one is null and the other is not return false
    	if(one == null || other == null) return false;
    	
    	// if they are not of the same length return false
    	if(one.length != other.length) return false;
    	
    	// compare byte by byte
    	for(int i = 0; i < one.length; i++){
    		if(one[i] != other[i]) return false;
    	}
    	// if no difference is found return true
    	return true;
    }
    
    /**
     * Fills the given byte array with value byte to the length
     * @param in
     * @param value
     * @param length
     * @return a new byte array of size length or null if arguments are wrong
     */
    public static byte[] fill(byte[] in, byte value, int length){
    	if(in == null || length <= 0) return in;
    	
    	// the output byte array
    	byte[] out = new byte[length];
    	
    	// if the given array is bigger than the requested length
    	if(in.length > length){
    		// just copy the first length bytes
    		for(int i = 0; i < length; i++)
    			out[i] = in[i];
    	}
    	// else if the input is smaller fill it with the value
    	else{
    		// first copy the input byte array
    		int i;
    		for(i = 0; i < in.length; i++){
    			out[i] = in[i];
    		}
    		
    		// now fill the rest with zeros
    		for(; i < length; i++){
    			out[i] = value;
    		}
    	}
    	// finally return the result
    	return out;
    }

    public static byte[] reset(byte[] in){
        if(in == null) return null;
        else
            for(int i = 0; i < in.length; i++){
                in[i] = (byte)0x00;
            }
        return in;
    }
    
    public static byte[][] chop(byte[] in, int size){
    	
    	// if argument is null return null
    	if(in == null || size <=0) return null;
    	// if argument is smaller than requested length
    	// then return it directly
    	if(in.length <= size){
    		byte[][] ret = new byte[1][];
    		ret[0] = in;
    		return ret;
    	}
    	
    	// now we know that size < in.length
    	
    	// get the number of piecies
    	int piecies = (int) in.length / size;
    	
    	// if there is a remainnder add on for the last part
    	if(in.length % size != 0) piecies = piecies + 1;
    	
    	
    	byte[][] ret = new byte[piecies][];
    	
    	
    	for(int i = 0; i < piecies; i++){
    		ret[i] = utils.copy(in, i * size, size);
    	}
    	return ret;
    }
    /**
     * Serializes an object to a byte array
     * @param obj
     * @return the serialized object or null if something goes wrong
     */
    public static byte[]  objectToBytes(Serializable obj){
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos;
		try {
			oos = new ObjectOutputStream(baos);
			oos.writeObject(obj);
		} catch (IOException e) {
			return null;
		}
		
		return baos.toByteArray();
    }
    
    /**
     * Creates an object from a byte array
     * @param bytes
     * @return an object or null if something goes wrong
     */
    public static Object bytesToObject(byte[] bytes){
		ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
		ObjectInputStream ois;
		try {
			ois = new ObjectInputStream(bais);
			return ois.readObject();
		} catch (Exception e) {
			return null;
		}
    }
		


         /********************************************************************************
	 * saves bytes to file
	 * @param file
	 * @param data
	 * @param key
	 * @return true if all goes well false if not
	 */
	public static boolean save(File file, byte[] data){
		// argument check
		if(file == null || data == null) return false;

		// now open the file output stream
		DataOutputStream out = null;
		try {
			out = new DataOutputStream(new FileOutputStream(file));
		} catch (FileNotFoundException e) {
			return false;
		}

		// and finaly write to the file
		for(int k=0; k < data.length; k++){
			try {
				out.writeByte(data[k]);
			} catch (IOException e) {
				return false;
			}
		}
		// close the file when done
		try {
			out.close();
		} catch (IOException e) {
			return false;
		}

		return true;
	}

	/**************************************************************************************
	 * reads a file, decrypts it with the given key, verifies the integrity of the hash and
	 * returns the read bytes or null if something is wrong
	 * @param file
	 * @param key
	 * @return the read bytes or null if something is wrong
	 */
	public static byte[] load(File file ){
	// argument check
	if(file == null)  return null;

	// open the file input stream
        InputStream is = null;
		try {
			is = new FileInputStream(file);
		} catch (FileNotFoundException e2) {
			return null;
		}
        // Get the size of the file
        long length = file.length();

        if (length > Integer.MAX_VALUE) {
            return null;
        }
        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        try {
        while (offset < bytes.length
			       && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
			    offset += numRead;
			}
		} catch (IOException e1) {
			return null;
		}

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            return null;
        }

        // Close the input stream
        try {
			is.close();
		} catch (IOException e) {
			return null;
		}

        return bytes;
    }

        public static  byte[] long_to_bytes(long num){
            byte[] out = new byte[8];
            for(int i = 0; i < 8; i++){
                out[7 - i] = (byte)(num >>> (i * 8));
            }
            byte[] out_ = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
            return utils.concat(out_, out);
            
        }

        public static long bytes_to_long(byte[] b){
            long l = 0;
            for(int i =0; i < 16; i++){
                   l <<= 8;
                   l ^= (long)b[i] & 0xFF;
            }
            return l;

        }

}
