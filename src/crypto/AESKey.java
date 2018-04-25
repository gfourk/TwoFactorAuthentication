package crypto;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import utils.utils;

public class AESKey implements SecretKey {
	
	private static final long serialVersionUID = 1L;
	
	// an internal key for the inherited methods
	private SecretKey internalKey;
	// the 32 bytes of the key
	private byte[] encoded;

	/**
	 * Default constructor initializes the key to a random secure key
	 */
	public AESKey() {
		// make a KeyGenerator object for AES 
		KeyGenerator AES_keygen = null;
		try { AES_keygen = KeyGenerator.getInstance ("AES");
		} catch (NoSuchAlgorithmException e) {
			// this should never happen
			System.out.println("ERROR - AES_keygen = KeyGenerator.getInstance (AES); - class AESKey");
			System.exit(0);
		}
		// init the generator to produce 256-bit keys and use a random seed
		AES_keygen.init (256, new SecureRandom());
		this.internalKey = AES_keygen.generateKey ();
		this.encoded = this.internalKey.getEncoded();
	}
	
	/**
	 * overloaded constructor creates a key from the bytes given
	 * @param keybytes
	 */
	public AESKey(byte[] keybytes) {
		// make a KeyGenerator object for AES 
		KeyGenerator AES_keygen = null;
		try { AES_keygen = KeyGenerator.getInstance ("AES");
		} catch (NoSuchAlgorithmException e) {
			// this should never happen
			System.out.println("ERROR - AES_keygen = KeyGenerator.getInstance (AES); - class AESKey");
			System.exit(0);
		}
		// init the generator to produce 256-bit keys and use a random seed
		AES_keygen.init (256, new SecureRandom());
		this.internalKey = AES_keygen.generateKey ();
		
		// now set the encoded bytes
		// if given input is less than 32 bytes (256 bits then fill with zeros)
		byte[] key256 = utils.fill(keybytes, (byte) 0x00, 32);
		// copy the filled array
		this.encoded = utils.copy(key256);
	}
	
	public AESKey(String password){
		// make a KeyGenerator object for AES 
		KeyGenerator AES_keygen = null;
		try { AES_keygen = KeyGenerator.getInstance ("AES");
		} catch (NoSuchAlgorithmException e) {
			// this should never happen
			System.out.println("ERROR - AES_keygen = KeyGenerator.getInstance (AES); - class AESKey");
			System.exit(0);
		}
		// init the generator to produce 256-bit keys and use a random seed
		AES_keygen.init (256, new SecureRandom());
		this.internalKey = AES_keygen.generateKey ();
		
		// get the hash of the password
		byte[] h = crypt.hash(password.getBytes());
		
		// get the hash to 32 bytes just in case...
		this.encoded = utils.fill(h, (byte)0x00, 32);
	}

	// overloaded functions
	@Override
	public String getAlgorithm() {
		return this.internalKey.getAlgorithm();
	}

	@Override
	public byte[] getEncoded() {
		// return a copy just in case
		return utils.copy(this.encoded);
	}

	@Override
	public String getFormat() {
		return this.internalKey.getFormat();
	}

}
