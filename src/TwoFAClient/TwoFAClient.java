package TwoFAClient;

import SecureChannel.SC;
import crypto.AESKey;
import crypto.HY457Certificate;
import crypto.crypt;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.StringTokenizer;
import utils.*;

public class TwoFAClient {

	// the clients RSA key pair

	private KeyPair kp;
	private String username;
	private String password;
	public boolean logged_in;
	private PublicKey server_key;

	public String register(String PIN, String port, String host) {

		int port_number;

		try {
			port_number = Integer.parseInt(port);
		} catch (Exception e) {
			Log.log("Error (0)", 1);
			return null;
		}

		try {
			// Try to open a socket on a given host and port
			Socket clientSocket = new Socket(host, port_number);
			clientSocket.setSoTimeout(0);
			// Try to open input and output streams
			PrintStream os = new PrintStream(clientSocket.getOutputStream());
			BufferedReader is = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

			if (clientSocket == null || os == null || is == null) {
				Log.log("Error (3)", 1);
				clientSocket.close();
				return null;
			}

			String response = null;

			// =============================================================================
			// #1 out
			// create the first message ( R - <user name> - user's Public Key )
			int nonce = Math.abs(new SecureRandom().nextInt());
			String msg = "";
			msg += nonce;
			msg += "-";
			msg += this.username;
			msg += "-";
			msg += utils.toHex(utils.objectToBytes(this.kp.getPublic()));

			try {
				// encrypt the first msg with the servers public key
				msg = utils.toHex(crypt.RSAEncrypt(msg.getBytes(), this.server_key));
			} catch (Exception ex) {
				Log.log("Error (4)", 1);
				clientSocket.close();
				return null;
			}

			// send the fisrt msg
			os.println(msg);
			Log.log("Sent: " + "<<Nonce,Name,PublicKey>>" + "Nonce: " + nonce + " Name: " + this.username, 1);

			// ================================================================================
			// #2 in
			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (5)", 1);
				clientSocket.close();
				return null;
			}
			try {
				response = new String(crypt.RSADecrypt(crypt.RSADecrypt(utils.toByte(response), this.kp.getPrivate()),
						this.server_key));
			} catch (Exception e) {
				Log.log("Error (6)", 1);
				clientSocket.close();
				return null;
			}

			StringTokenizer st = new StringTokenizer(response, "-");

			long nonce_1 = 0;
			AESKey sessionKey = null;
			if (st.hasMoreTokens())
				nonce_1 = Long.parseLong(st.nextToken());
			if (st.hasMoreTokens())
				try {
					sessionKey = (AESKey) utils.bytesToObject(utils.toByte(st.nextToken()));
				} catch (Exception e) {
					Log.log("Error (7)", 1);
					clientSocket.close();
					return null;
				}
			else {
				Log.log("Error (8)", 1);
				clientSocket.close();
				return null;
			}

			if (nonce_1 != nonce + 1) {
				Log.log("Error (9)", 1);
				clientSocket.close();
				return null;
			}
			Log.log("Received: <<Nonce+1,Session Key>> Nonce+1: " + nonce_1, 1);

			// =============================================================================
			// #3 out
			nonce = nonce + 2;
			response = "" + nonce + "-" + utils.toHex(utils.objectToBytes(sessionKey));

			try {
				response = utils.toHex(crypt.RSAEncrypt((crypt.RSAEncrypt(response.getBytes(), this.kp.getPrivate())),
						this.server_key));
			} catch (Exception e) {
				Log.log("Error (10)", 1);
				clientSocket.close();
				return null;
			}

			os.println(response);
			Log.log("Sent: <<Nonce+2,Session Key>> Nonce+2: " + nonce, 1);

			// =================================================================== end of
			// negotiations

			// ===================================================================

			// ================================================================ REGISTER
			// REQUEST
			SC sc = new SC(this.username, "Server", sessionKey, 0, 0, 4000);

			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (11)", 1);
				clientSocket.close();
				return null;
			}

			try {
				this.wait(500);
			} catch (Exception e) {
				;
			}
			response = sc.decrypt_msg(response);

			if (response.equals("What is it?") == false) {
				Log.log("Error (12)", 1);
				clientSocket.close();
				return null;
			}
			Log.log("SC Received: " + "What is it?", 1);

			response = "I want to register";

			response = sc.encrypt_msg(response);

			try {
				this.wait(500);
			} catch (Exception e) {
				;
			}
			os.println(response);

			Log.log("SC Sent: " + "I want to register", 1);

			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (13)", 1);
				clientSocket.close();
				return null;
			}

			response = sc.decrypt_msg(response);

			if (response.equals("What is your PIN?") == false) {
				Log.log("Error (14)", 1);
				clientSocket.close();
				return null;
			}

			Log.log("SC Received: " + "What is your PIN?", 1);

			response = sc.encrypt_msg(PIN);
			try {
				this.wait(500);
			} catch (Exception e) {
				;
			}
			os.println(response);

			Log.log("SC Sent: " + "PIN: " + PIN, 1);

			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (15)", 1);
				clientSocket.close();
				return null;
			}

			response = sc.decrypt_msg(response);

			Log.log("SC Received: " + "RegCode: " + response, 1);

			try {
				clientSocket.close();
			} catch (IOException ex) {
				Log.log("Error (X)", 1);
				clientSocket.close();
				return null;
			}

			return response;
		} catch (UnknownHostException e) {
			Log.log("Error (1)", 1);
			return null;
		} catch (IOException e) {
			Log.log("Error (2)", 1);
			return null;
		}

	}

	public String get_OTP(String PIN, String port, String host) {

		int port_number;
		try {
			port_number = Integer.parseInt(port);
		} catch (Exception e) {
			Log.log("Error (30)", 1);
			return null;
		}

		try {
			// Try to open a socket on a given host and port
			Socket clientSocket = new Socket(host, port_number);
			clientSocket.setSoTimeout(0);
			// Try to open input and output streams
			PrintStream os = new PrintStream(clientSocket.getOutputStream());
			BufferedReader is = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

			if (clientSocket == null || os == null || is == null) {
				Log.log("Error (33)", 1);
				clientSocket.close();
				return null;
			}

			String response = null;

			// =============================================================================
			// #1 out
			// create the first message ( R - <user name> - user's Public Key )
			int nonce = Math.abs(new SecureRandom().nextInt());
			String msg = "";
			msg += nonce;
			msg += "-";
			msg += this.username;
			msg += "-";
			msg += utils.toHex(utils.objectToBytes(this.kp.getPublic()));

			try {
				// encrypt the first msg with the servers public key
				msg = utils.toHex(crypt.RSAEncrypt(msg.getBytes(), this.server_key));
			} catch (Exception ex) {
				Log.log("Error (34)", 1);
				clientSocket.close();
				return null;
			}

			// send the fisrt msg
			os.println(msg);
			Log.log("Sent: " + "<<Nonce,Name,PublicKey>>" + "Nonce: " + nonce + " Name: " + this.username, 1);

			// ================================================================================
			// #2 in
			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (35)", 1);
				clientSocket.close();
				return null;
			}
			try {
				response = new String(crypt.RSADecrypt(crypt.RSADecrypt(utils.toByte(response), this.kp.getPrivate()),
						this.server_key));
			} catch (Exception e) {
				Log.log("Error (36)", 1);
				clientSocket.close();
				return null;
			}

			StringTokenizer st = new StringTokenizer(response, "-");

			long nonce_1 = 0;
			AESKey sessionKey = null;
			if (st.hasMoreTokens())
				nonce_1 = Long.parseLong(st.nextToken());
			if (st.hasMoreTokens())
				try {
					sessionKey = (AESKey) utils.bytesToObject(utils.toByte(st.nextToken()));
				} catch (Exception e) {
					Log.log("Error (37)", 1);
					clientSocket.close();
					return null;
				}
			else {
				Log.log("Error (38)", 1);
				clientSocket.close();
				return null;
			}

			if (nonce_1 != nonce + 1) {
				Log.log("Error (39)", 1);
				clientSocket.close();
				return null;
			}
			Log.log("Received: <<Nonce+1,Session Key>> Nonce+1: " + nonce_1, 1);

			// =============================================================================
			// #3 out
			nonce = nonce + 2;
			response = "" + nonce + "-" + utils.toHex(utils.objectToBytes(sessionKey));

			try {
				response = utils.toHex(crypt.RSAEncrypt((crypt.RSAEncrypt(response.getBytes(), this.kp.getPrivate())),
						this.server_key));
			} catch (Exception e) {
				Log.log("Error (310)", 1);
				clientSocket.close();
				return null;
			}

			os.println(response);
			Log.log("Sent: <<Nonce+2,Session Key>> Nonce+2: " + nonce, 1);

			// =================================================================== end of
			// negotiations

			// ===================================================================

			// ================================================================ OTP REQUEST
			SC sc = new SC(this.username, "Server", sessionKey, 0, 0, 4000);

			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (311)", 1);
				clientSocket.close();
				return null;
			}

			try {
				this.wait(500);
			} catch (Exception e) {
				;
			}
			response = sc.decrypt_msg(response);

			if (response.equals("What is it?") == false) {
				Log.log("Error (312)", 1);
				clientSocket.close();
				return null;
			}
			Log.log("SC Received: " + "What is it?", 1);

			response = "I want an OTP";

			response = sc.encrypt_msg(response);

			try {
				this.wait(500);
			} catch (Exception e) {
				;
			}
			os.println(response);

			Log.log("SC Sent: " + "I want an OTP", 1);

			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (313)", 1);
				clientSocket.close();
				return null;
			}

			response = sc.decrypt_msg(response);

			if (response.equals("What is your PIN?") == false) {
				Log.log("Error (314)", 1);
				clientSocket.close();
				return null;
			}

			Log.log("SC Received: " + "What is your PIN?", 1);

			response = sc.encrypt_msg(PIN);
			try {
				this.wait(500);
			} catch (Exception e) {
				;
			}
			os.println(response);

			Log.log("SC Sent: " + "PIN: " + PIN, 1);

			try {
				response = is.readLine();
			} catch (IOException e) {
				Log.log("Error (315)", 1);
				clientSocket.close();
				return null;
			}

			response = sc.decrypt_msg(response);

			Log.log("SC Received: " + "OTP: " + response, 1);

			try {
				clientSocket.close();
			} catch (IOException ex) {
				Log.log("Error (X)", 1);
				clientSocket.close();
				return null;
			}

			return response;

		} catch (UnknownHostException e) {
			Log.log("Error (31)", 1);
			return null;
		} catch (IOException e) {
			Log.log("Error (32)", 1);
			return null;
		}

	}

	

	/**
	 * Loads a file with all its data
	 * 
	 * @param file
	 * @param password
	 * @return
	 */
	public boolean load_file(File file, String password) {
		byte[] data = crypt.loadDecrypt(file, new AESKey(password));
		this.password = password;
		boolean result = this.unpack_state(data);
		this.logged_in = result;
		return result;
	}

	/**
	 * creates file from the state
	 * 
	 * @param text
	 * @param string
	 * @return
	 */
	public boolean create_file(String username, String password) {
		this.username = username;
		this.password = password;
		this.kp = crypt.getRSAKeyPair();

		boolean result = crypt.saveEncrypt(new File(username + ".client"), this.pack_state(), new AESKey(password));
		this.logged_in = result;
		return result;
	}

	/**
	 * saves and exits
	 * 
	 * @return
	 */
	public boolean save_and_exit() {

		if (this.logged_in == false)
			return false;

		byte[] state = this.pack_state();
		if (state == null)
			return false;
		else
			return crypt.saveEncrypt(new File(this.username + ".client"), state, new AESKey(this.password));
	}

	/**
	 * Loads the servers certificate
	 * 
	 * @param file
	 * @return
	 */
	public boolean load_server_cert(File file) {

		byte[] cert_bytes = utils.load(file);
		if (cert_bytes == null)
			return false;
		HY457Certificate server_cert = null;
		try {
			server_cert = (HY457Certificate) utils.bytesToObject(cert_bytes);
			if (server_cert.check(server_cert.getPublicKey()) == false)
				return false;
			if (server_cert.getOwner().equals("2FAServer") == false)
				return false;
			if (server_cert.getIssuer().equals("2FAServer") == false)
				return false;
		} catch (Exception e) {
			return false;
		}

		this.server_key = server_cert.getPublicKey();

		return true;

	}

	/**
	 * packs the state of the client in a byte array to be saved in a file
	 */
	private byte[] pack_state() {
		byte[] username_bytes = this.username.getBytes();
		String username_hex_str = utils.toHex(username_bytes);

		byte[] rsa_bytes = utils.objectToBytes(this.kp);
		String rsa_hex_str = utils.toHex(rsa_bytes);

		String res = username_hex_str + " " + rsa_hex_str;

		byte[] data = res.getBytes();

		return data;
	}

	/**
	 * unpacks the state from a byte array
	 * 
	 * @param data
	 * @return true for succes false for failure
	 */
	private boolean unpack_state(byte[] data) {

		if (data == null)
			return false;

		String res = new String(data);

		StringTokenizer st = new StringTokenizer(res, " ");

		String username_hex_str = null;
		String rsa_hex_str = null;

		if (st.hasMoreTokens())
			username_hex_str = st.nextToken();
		if (st.hasMoreTokens())
			rsa_hex_str = st.nextToken();
		else
			return false;

		byte[] username_bytes = utils.toByte(username_hex_str);
		byte[] rsa_bytes = utils.toByte(rsa_hex_str);

		this.username = new String(username_bytes);
		this.kp = (KeyPair) utils.bytesToObject(rsa_bytes);

		return true;
	}

}
