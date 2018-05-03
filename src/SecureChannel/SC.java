package SecureChannel;

import crypto.AESKey;
import crypto.crypt;
import utils.*;

/**
 * This class implements the secure channel
 *
 *
 */
public class SC {

	// message counters
	private long last_received;
	private long last_sent;

	// the XI in hex string form
	private String xi;

	// keys
	private AESKey KeySendEnc; // KeySendEnc - SHA-256 (K || Enc Alice to Bob�)
	private AESKey KeyRecEnc; // KeyRecEnc - SHA-256 (K || Enc Bob to Alice�)
	private AESKey KeySendAuth; // KeySendAuth - SHA-256 (K || Auth Alice to Bob�)
	private AESKey KeyRecAuth; // KeyRecAuth - SHA-256 (K || Auth Bob to Alice�)

	/*****************************************************************************
	 * Constructor
	 * 
	 * @param my_name
	 * @param other_name
	 */
	public SC(String my_name, String other_name, AESKey sessionKey, long last_received, long last_sent, int max_time) {
		this.last_received = last_received;
		this.last_sent = last_sent;
		this.xi = utils.toHex("HY457 Secure Channel".getBytes());

		this.KeySendEnc = new AESKey(
				crypt.hash(utils.concat(sessionKey.getEncoded(), ("Enc " + my_name + " to " + other_name).getBytes())));
		this.KeyRecEnc = new AESKey(
				crypt.hash(utils.concat(sessionKey.getEncoded(), ("Enc " + other_name + " to " + my_name).getBytes())));
		this.KeySendAuth = new AESKey(crypt
				.hash(utils.concat(sessionKey.getEncoded(), ("Auth " + my_name + " to " + other_name).getBytes())));
		this.KeyRecAuth = new AESKey(crypt
				.hash(utils.concat(sessionKey.getEncoded(), ("Auth " + other_name + " to " + my_name).getBytes())));
	}

	/****************************************************************************
	 * creates a MAC for the msg as --Input: i || length(xi) || xi || mi--
	 * 
	 * @param msg
	 * @return HMAC-SHA-256 (KeySendAuth, i || length(x) || x || m)
	 */
	private byte[] create_MAC(byte[] msg) {
		// create a hex string of :
		String signed = utils.toHex(this.KeySendAuth.getEncoded()) // the auth key
				+ utils.toHex(("" + this.last_sent + 1).getBytes()) // next msg number
				+ utils.toHex(("" + this.xi.length()).getBytes()) // the length of xi
				+ this.xi // the xi
				+ utils.toHex(msg); // the msg itself

		// and return its hash in a byte array
		return crypt.hash(utils.toByte(signed));
	}

	private byte[] create_other_MAC(byte[] msg) {
		// create a hex string of :
		String signed = utils.toHex(this.KeyRecAuth.getEncoded()) // the auth key
				+ utils.toHex(("" + this.last_received + 1).getBytes()) // next msg number
				+ utils.toHex(("" + this.xi.length()).getBytes()) // the length of xi
				+ this.xi // the xi
				+ utils.toHex(msg); // the msg itself

		// and return its hash in a byte array
		return crypt.hash(utils.toByte(signed));
	}

	private byte[] getMAC(byte[] msg) {
		return utils.copy(msg, msg.length - 32, 32);
	}

	private byte[] getmsg(byte[] msg) {
		return utils.copy(msg, 16, msg.length - 48);
	}

	private byte[] get_time(byte[] msg) {
		return utils.copy(msg, 0, 16);
	}

	private boolean check_time(byte[] btime) {
		return true;
		/*
		 * long time = utils.bytes_to_long(btime); if(time + this.max_time >
		 * System.currentTimeMillis()) return false; else return true;
		 */
	}

	/**
	 *
	 * @param msg
	 * @return
	 */
	// creates a secure msg
	public String encrypt_msg(String msg) {

		if (msg == null) {
			return null;
		}
		byte[] msg_bytes = msg.getBytes();
		msg_bytes = utils.concat(utils.long_to_bytes(System.currentTimeMillis()), msg_bytes);
		msg_bytes = utils.concat(msg_bytes, this.create_MAC(msg_bytes));

		String res = null;
		try {
			res = utils.toHex(crypt.AESEncrypt(msg_bytes, this.KeySendEnc, this.last_sent + 1));
		} catch (Exception ex) {
			return null;
		}
		this.last_sent++;
		return res;
	}

	/**
	 *
	 * @param msg
	 * @return
	 */
	public String decrypt_msg(String msg) {
		if (msg == null)
			return null;

		// get the bytes from the hex
		byte[] msg_bytes = utils.toByte(msg);
		byte[] decrypted = null;
		try {
			// decrypt
			decrypted = crypt.AESDecrypt(msg_bytes, this.KeyRecEnc, this.last_received + 1);
		} catch (Exception e) {
			return null;
		}

		byte[] pure_msg = this.getmsg(decrypted);
		byte[] mac = this.getMAC(decrypted);
		byte[] time = this.get_time(decrypted);

		// check time
		if (this.check_time(time) == false) {
			return null;
		}

		// verify the mac
		byte[] new_mac = this.create_other_MAC(utils.concat(time, pure_msg));

		if (utils.compare(mac, new_mac) == false) {
			return null;
		}

		this.last_received++;
		return new String(pure_msg);
	}

}
