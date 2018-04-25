package main;

import SecureChannel.SC;
import java.io.File;
import java.security.*;

import crypto.*;
import utils.*;

public class main {

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {


		/******************************************** utils tests *

		byte[] a = new byte[21];

		byte[][] b = utils.chop(a, 3);

		for(int i = 0; i < b.length; i++)
			System.out.println(utils.toHex(b[i]));

		System.out.println(b.length);


		***********************************************************/






		/******************************************** AES TESTS *
		byte[] keybytes = {'S', 'E', 'C', 'R', 'E', 'T'};
		 AESKey key = new AESKey(keybytes);

		 key = new AESKey("adsdasdsada");

		 byte plaintext [] = {'S', 'E', 'C', 'R', 'E', 'T'};

		 plaintext = utils.fill(plaintext, (byte)0x00, 500);

		 System.out.println("Plaintext: "+utils.toHex(plaintext));

		 byte[] ciphertext = crypt.AESEncrypt(plaintext, key);
		 System.out.println("Ciphertext: "+utils.toHex(ciphertext));

		 byte[] keybytes1 = {'S', 'E', 'C', 'R', 'E', 'T'};
		 key = new AESKey(keybytes1);

		 key = new AESKey("adsdasdsada");

		 byte[] deciphered = crypt.AESDecrypt(ciphertext, key);

		 System.out.println("Deciphered: "+utils.toHex(deciphered));

		 System.out.println(utils.compare(plaintext, deciphered));

		 System.out.println("filled: "+utils.toHex(
				 utils.fill(deciphered, (byte)0x00, 6)));

		 System.out.println(ciphertext.length);

		 System.out.println(utils.toHex(crypt.hash(plaintext)) + "---"+crypt.hash(plaintext).length);

		**********************************************************/

		/************************** RSA TESTS **************************/

		 /*

		byte[] plaintext = {'S'};

		plaintext = utils.fill(plaintext, (byte) 0xff, 500);

		byte[] ciphertext = null;

		KeyPair kp = crypt.getRSAKeyPair();

		System.out.println("Plaintext: "+utils.toHex(plaintext));
		System.out.println("length: "+plaintext.length);

		ciphertext = crypt.RSAEncrypt(plaintext, kp.getPrivate());

		System.out.println("Ciphertext: "+ utils.toHex(ciphertext));
		System.out.println("length: "+ciphertext.length);

		plaintext = crypt.RSADecrypt(ciphertext, kp.getPublic());

		System.out.println("Plaintext: "+utils.toHex(plaintext));
		System.out.println("length: "+plaintext.length);

		///////////////////////////////////////////////////
		System.out.println("-------------------------------------------------------");

		System.out.println("Plaintext: "+utils.toHex(plaintext));
		System.out.println("length: "+plaintext.length);

		ciphertext = crypt.RSAEncrypt(plaintext, kp.getPublic());

		System.out.println("Ciphertext: "+ utils.toHex(ciphertext));
		System.out.println("length: "+ciphertext.length);

		plaintext = crypt.RSADecrypt(ciphertext, kp.getPrivate());

		System.out.println("Plaintext: "+utils.toHex(plaintext));
		System.out.println("length: "+plaintext.length);

		*/

		/*************************************************************/

		/*************************************************** SIGNATURES TESTS */

		/*
		KeyPair kp = crypt.getRSAKeyPair();
		KeyPair kp1 = crypt.getRSAKeyPair();

		byte[] msg = {'t','e','s','t','_','m','s','g'};

		msg = utils.fill(msg, (byte) 0x00, 1500);
		System.out.println("Message: "+utils.toHex(msg));
		System.out.println("Length: "+msg.length);


		byte[] signature = crypt.getSignature(msg, kp.getPrivate());

		System.out.println("Signature: "+utils.toHex(signature));
		System.out.println("Length: "+signature.length);

		boolean result = crypt.verifySignature(msg, kp.getPublic(), signature);

		System.out.println("Verified: "+result);

		*/

		/********************************************** save and load test */

		/*
		byte[] msg = "this is my message".getBytes();

		AESKey key = new AESKey();

		File f = new File("file.txt");

		boolean result = crypt.saveEncrypt(f, msg, key);

		System.out.println("Save Result: "+result);

		// load the file data
		byte[] read_data = crypt.loadDecrypt(f, key);

		System.out.println("Read from file: "+new String(read_data));

		*/

		/*********************************************** object serialization tests */

		/*
		AESKey key = new AESKey();

		byte[] a = utils.objectToBytes(key);

		key = (AESKey)utils.bytesToObject(a);

		*/

		/*****************************************************************************/
/*
            for(int i = 1; i < 100; i++)
            Log.log("sdfsdfdsfsdfdsfdddsf", i%3+1);
 * 
             KeyPair kp = crypt.getRSAKeyPair();

            HY457Certificate s = new HY457Certificate ("2FAServerasdasda", "2FAServer", kp.getPrivate(), kp.getPublic());

            utils.save(new File("bad.cert"), utils.objectToBytes(s));
*/
/*
            long a = 255;

            byte[] lala = utils.long_to_bytes(a);

            System.out.println(a);
            System.out.println(utils.toHex(lala));
            */

//
//            byte[] lala = {(byte) 0x00,(byte) 0x00};
//
//            lala = utils.fill( lala ,(byte)0x01 , 100 );
//
//            System.out.println(utils.getMAC(lala).length);
//            System.out.println(utils.getmsg(lala).length);


            //System.out.println(utils.bytes_to_long(utils.long_to_bytes()));
/*
            AESKey k = new AESKey();

            SC name1 = new SC("name1","name2",k, 0, 0,1000);
            SC name2 = new SC("name2","name1",k, 0, 0,1000);


            for(int i = 0; i < 100; i++){
                String msg = "this is a message";

                String encr1 = name1.encrypt_msg(msg+i);
                System.out.println("name 1 encrypted #"+name1.last_sent);
                System.out.println("P1 encrypted: "+encr1);

                String encr2 = name2.decrypt_msg(encr1);
                System.out.println("name 2 decrypted #"+name2.last_received);
                System.out.println("P2 decrypted: "+encr2);

                encr1 = name2.encrypt_msg(msg+i);
                System.out.println("name 2 encrypted #"+name2.last_sent);
                System.out.println("P2 encrypted: "+encr1);

                encr2 = name1.decrypt_msg(encr1);
                System.out.println("name 1 decrypted #"+name1.last_received);
                System.out.println("P1 decrypted: "+encr2);
    
            }


 */
	} // END OF MAIN





}
