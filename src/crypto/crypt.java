package crypto;


import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import utils.Log;
import utils.utils;

// chapter 6 X509 Certificates

public class crypt {
	
	/*****************************************************************************
	 * Encrypt the plaintext with the AES Cipher CBC mode
	 * @param plaintext
	 * @param key
	 * @return the ciphertext
	 * @throws Exception 
	 */
	public static byte[] AESEncrypt(byte[] plaintext, AESKey key) throws Exception {
		Cipher AES_Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		AES_Cipher.init (Cipher.ENCRYPT_MODE, key,new IvParameterSpec( utils.fill(crypt.hash(key.getEncoded()),(byte)0x00,16)));
		return AES_Cipher.doFinal (plaintext);
	}

        	/*****************************************************************************
	 * Encrypt the plaintext with the AES Cipher CBC mode
	 * @param plaintext
	 * @param key
	 * @return the ciphertext
	 * @throws Exception
	 */
	public static byte[] AESEncrypt(byte[] plaintext, AESKey key, long counter) throws Exception {
		Cipher AES_Cipher = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");
		AES_Cipher.init (Cipher.ENCRYPT_MODE, key,new IvParameterSpec(utils.long_to_bytes(counter) ));
		return AES_Cipher.doFinal (plaintext);
	}

	/*******************************************************************************
	 * Decrypts the plaintext using AES CTR mode
	 * @param ciphertext
	 * @param key
	 * @return the decrypted plaintext
	 */
	public static byte[] AESDecrypt(byte[] ciphertext, AESKey key) throws Exception {
		Cipher AES_Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		AES_Cipher.init (Cipher.DECRYPT_MODE, key,new IvParameterSpec( utils.fill(crypt.hash(key.getEncoded()),(byte)0x00,16)));
		return AES_Cipher.doFinal (ciphertext);
	}


	/*******************************************************************************
	 * Decrypts the plaintext using AES CTR mode
	 * @param ciphertext
	 * @param key
	 * @return the decrypted plaintext
	 */
	public static byte[] AESDecrypt(byte[] ciphertext, AESKey key,long counter) throws Exception {
		Cipher AES_Cipher = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");
		AES_Cipher.init (Cipher.DECRYPT_MODE, key,new IvParameterSpec( utils.long_to_bytes(counter)));
		return AES_Cipher.doFinal (ciphertext);
	}
	
	/*********************************************************************************
	 * Encrypts the plaintext using the RSA cipher
	 * @param plaintext
	 * @param key
	 * @return the encrypted plaintext
	 * @throws Exception
	 */
	public static byte[] RSAEncrypt(byte[] plaintext, Key key ) throws Exception {
		// get a cipher
		Cipher c = Cipher.getInstance("RSA/None/NoPadding");
		// initialize to encrypt
		c.init(Cipher.ENCRYPT_MODE, key);
		// get the max block size so as to chop the plaintext if necessary
		int size = c.getBlockSize();
		// chop the plaintext
		byte[][] plaintexts = utils.chop(plaintext, size);
		byte[] ciphertext = null;
		
		byte[] temp;
		// now encrypt all the blocks
		for(int i = 0; i < plaintexts.length; i++){
			temp = c.doFinal(plaintexts[i]);
			ciphertext = utils.concat(ciphertext, temp);
		}
		return ciphertext;
	}
	
	/***********************************************************************************
	 * Decrypts the ciphertext using the RSA Cipher
	 * @param ciphertext
	 * @param key
	 * @return the decrypted ciphertext
	 * @throws Exception
	 */
	public static byte[] RSADecrypt(byte[] ciphertext, Key key ) throws Exception {
		// get a cipher
		Cipher c = Cipher.getInstance("RSA/None/NoPadding");
		// initialize to decrypt
		c.init(Cipher.DECRYPT_MODE, key);
		// get the max block size so as to chop the plaintext if necessary
		int size = c.getBlockSize();
		// chop the plaintext
		byte[][] ciphertexts = utils.chop(ciphertext, size);
		byte[] plaintext = null;
		
		byte[] temp;
		// now decrypt all the blocks
		for(int i = 0; i < ciphertexts.length; i++){
			temp = c.doFinal(ciphertexts[i]);
			plaintext = utils.concat(plaintext, temp);
		}
		return plaintext;
	}
	
	/**************************************************************************************
	 * Signs the message using the private key provides
	 * @param msg
	 * @param key
	 * @return the signature for that message
	 * @throws Exception
	 */
	public static byte[] getSignature(byte[] msg, PrivateKey key) throws Exception{
		// argument check
		if(msg == null || key == null) return null;
		// get a Signature instance
		Signature mySignature = Signature.getInstance("SHA256withRSA");
		// initialize
		mySignature.initSign(key);
		mySignature.update(msg);
		// sign and return
		return mySignature.sign();
	}
	
	/**************************************************************************************
	 * Verifies the signature for the message using the RSA public key provided
	 * @param msg
	 * @param key
	 * @param signature
	 * @return true if signature is valid false if not
	 * @throws Exception
	 */
	public static boolean verifySignature(byte[] msg, PublicKey key, byte[] signature) throws Exception{
		// argument check
		if(msg == null || key == null || signature == null) return false;
		// get a signature object
		Signature mySignature = Signature.getInstance("SHA256withRSA");
		mySignature.initVerify(key);
		mySignature.update(msg);
		return mySignature.verify(signature);
	}
	
	
	
	
	
	/************************************************************************************
	 * Returns the SHA 256 hash of the message
	 * @param msg
	 * @return the SHA-256 hash of the message
	 */
	public static byte[] hash(byte[] msg){
		try {
			return MessageDigest.getInstance("SHA256","BC").digest(msg);
		} catch (Exception e) {
			// this should never happen
			System.out.println("ERROR - crypt.hash()");
			System.exit(0);
		}
		
		return null;
	}
	
	/************************************************************************************
	 * Creates a new RSA keyPair of 1024 bits 
	 * @return a new RSA keyPair of 1024 bits
	 */
	public static KeyPair getRSAKeyPair(){
		// get a keypair generator
		KeyPairGenerator kpGen = null;
		try {
			kpGen = KeyPairGenerator.getInstance ("RSA");
		} catch (NoSuchAlgorithmException e) { 
			// this should never happen
                        System.out.println("ERROR - crypt.getRSAKeyPair");
			System.exit(0);
		}
		// initilaize it to 1024 bytes
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}
	
	/********************************************************************************
	 * Encrypts and saves the given data along with their hash at the beggining
	 * @param file
	 * @param data
	 * @param key
	 * @return true if all goes well false if not
	 */
	public static boolean saveEncrypt(File file, byte[] data, AESKey key ){
		// argument check
		if(file == null || data == null || key == null) return false;
		
		// digest the data, this adds 32 bytes to the data to be saved
		byte[] digested = crypt.hash(data);
		
		// concatenate the data with their hash
		data = utils.concat(digested, data);
		
		// first encrypt the data
		byte[] encrypted = null;
		try {
			encrypted = crypt.AESEncrypt(data, key);
		} catch (Exception e1) {
				return false;
		}
		// now open the file output stream
		DataOutputStream out = null;
		try {
			out = new DataOutputStream(new FileOutputStream(file));
		} catch (FileNotFoundException e) {
			return false;
		}
		
		// and finaly write to the file
		for(int k=0; k < encrypted.length; k++){
			try {
				out.writeByte(encrypted[k]);
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
	public static byte[] loadDecrypt(File file, AESKey key ){
		// argument check
		if(file == null || key == null) return null;

                //System.out.println("args not null");
	
		// open the file input stream
        InputStream is = null;
		try {
			is = new FileInputStream(file);
		} catch (FileNotFoundException e2) {
			return null;
		}
        //System.out.println("ainputstream not null");
        
        // Get the size of the file
        long length = file.length();
    
        if (length > Integer.MAX_VALUE) {
            return null;
        }
        //System.out.println("length is ok");
    
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
         //System.out.println("file was read ok");
    
        // Close the input stream 
        try {
			is.close();
		} catch (IOException e) {
			return null;
		}
          //System.out.println("file was closed ok");
        
        // now decrypt the bytes
        byte[] decrypted = null;
        
        try {
			decrypted = crypt.AESDecrypt(bytes, key);
		} catch (Exception e) {
			return null;
		}
         //System.out.println("contents decrypted ok");
		
		// get the 32 first bytes that are the hash
		byte[] digest = utils.copy(decrypted, 0, 32);
		// get the rest of the data
		byte[] msg = utils.copy(decrypted,32,(int) length);
		
		
		// now verify the hash
		// create the hash all over again
		byte[] new_digest = crypt.hash(msg);
		// now compare the two
		if(utils.compare(digest, new_digest)) 
			return msg;
		else 
			return null;

    }

        public static boolean password_ok(String password){
            if(password == null) return false;
            if(crypt.securityLevel(password) >=2 )
                return true;
            else return false;
        }

        public static boolean PIN_ok(String PIN){
            if(PIN != null && PIN.length() >=5 )return true;
            else return false;
        }

        public static boolean username_ok(String userame){
                return true;
        }

        /*returns the security level of the password*/
	static int securityLevel(String password){
		int digit = 0;
		int lower = 0;
		int upper = 0;
		int symbol = 0;
		int level = 0;
		char c;
		for(int i=0;i<password.length();++i){
			c = password.charAt(i);
			if( Character.isDigit(c) ){ digit = 1;}
			if( Character.isLowerCase(c) ){lower = 1;}
			if( Character.isUpperCase(c) ){upper = 1;}
			if( c=='*' || c=='/' || c=='+' || c=='-' || c=='.' || c==',' ||
				c=='$' || c=='#' || c=='@' || c=='%' || c=='^' || c=='&' ||
				c=='(' || c==')' || c=='[' || c==']' || c==';' || c==':' ||
				c=='\'' || c=='\"' || c=='\\' || c=='?'|| c=='<' || c=='>'  ||
				c=='|' || c=='{' || c=='}' || c=='=' || c=='_' || c=='~' || c=='!'){symbol = 1;}
		}
		level = digit+lower+upper+symbol;
		return level;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

}
