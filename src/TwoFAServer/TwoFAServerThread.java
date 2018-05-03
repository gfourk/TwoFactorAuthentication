package TwoFAServer;

import SecureChannel.SC;
import crypto.AESKey;
import crypto.crypt;
import java.io.*;
import java.net.*;
import java.util.StringTokenizer;
import utils.*;
import java.security.PublicKey;

class TwoFAServerThread extends Thread {

	// network stuff
	private DataInputStream is = null;
	private PrintStream os = null;
	private Socket clientSocket = null;
	private TwoFAServer server;

	/******************************************************************************
	 * constructor
	 ******************************************************************************/
	TwoFAServerThread(Socket clientSocket, TwoFAServer server) {
		this.clientSocket = clientSocket;
		this.server = server;
	}

	/*******************************************************************************
	 * the run method
	 * 
	 *******************************************************************************/
	@SuppressWarnings("deprecation")
	public void run() {
		String incomming = null;
		String outgoing = null;

		try {
			// open input and output streams
			is = new DataInputStream(clientSocket.getInputStream());
			os = new PrintStream(clientSocket.getOutputStream());

			// =================================================================================
			// #1 in
			incomming = is.readLine();
			if (incomming == null) {
				this.clientSocket.close();
				Log.log("Error (0)", 2);
				is.close();
				os.close();
				return;
			}

			try {
				incomming = new String(crypt.RSADecrypt(utils.toByte(incomming), this.server.kp.getPrivate()));
			} catch (Exception ex) {
				Log.log("Error (1)", 2);
				is.close();
				os.close();
				return;
			}

			StringTokenizer st = new StringTokenizer(incomming, "-");

			long nonce = 0;
			String name = null;
			PublicKey other_public = null;
			if (st.hasMoreTokens()) {
				nonce = Long.parseLong(st.nextToken());
			}
			if (st.hasMoreTokens()) {
				name = st.nextToken();
			}
			if (st.hasMoreTokens()) {
				try {
					other_public = (PublicKey) utils.bytesToObject(utils.toByte(st.nextToken()));
				} catch (Exception e) {
					Log.log("Error (2)", 2);
					is.close();
					os.close();
					return;
				}
			} else {
				Log.log("Error (3)", 2);
				is.close();
				os.close();
				return;
			}

			Log.log("Received: " + "<<Nonce,Name,Public Key>>" + " From: " + name + " Nonce: " + nonce, 2);

			// ==============================================================================
			// #2 out

			AESKey SessionKey = new AESKey();
			nonce = nonce + 1;
			outgoing = "" + nonce + "-" + utils.toHex(utils.objectToBytes(SessionKey));

			try {
				outgoing = utils.toHex(crypt.RSAEncrypt(
						(crypt.RSAEncrypt(outgoing.getBytes(), this.server.kp.getPrivate())), other_public));
			} catch (Exception e) {
				Log.log("Error (4)", 2);
				is.close();
				os.close();
				return;
			}

			os.println(outgoing);

			Log.log("Sent: " + "<<R+1,Session Key>>" + " Nonce: " + nonce, 2);

			// =============================================================================
			// #3 in
			incomming = is.readLine();
			if (incomming == null) {
				this.clientSocket.close();
				Log.log("Error (5)", 2);
				is.close();
				os.close();
				return;
			}
			try {
				incomming = new String(crypt.RSADecrypt(
						crypt.RSADecrypt(utils.toByte(incomming), this.server.kp.getPrivate()), other_public));
			} catch (Exception e) {
				Log.log("Error (6)", 2);
				is.close();
				os.close();
				return;
			}

			st = new StringTokenizer(incomming, "-");

			long nonce_1 = 0;
			AESKey received_SessionKey = null;
			if (st.hasMoreTokens())
				nonce_1 = Long.parseLong(st.nextToken());
			if (st.hasMoreTokens())
				try {
					received_SessionKey = (AESKey) utils.bytesToObject(utils.toByte(st.nextToken()));
				} catch (Exception e) {
					Log.log("Error (7)", 2);
					is.close();
					os.close();
					return;
				}
			else {
				Log.log("Error (8)", 2);
				return;
			}

			if (nonce_1 - 1 != nonce) {
				Log.log("Error (9)", 2);
				is.close();
				os.close();
				return;
			}
			if (!utils.compare(received_SessionKey.getEncoded(), SessionKey.getEncoded())) {
				Log.log("Error (10)", 2);
				is.close();
				os.close();
				return;
			}

			Log.log("Received: " + "<<Nonce+2,Session Key>>" + " From: " + name + " Nonce: " + nonce, 2);

			// ============================================================================
			// end of negotiations

			// make a secure channel
			SC sc = new SC("Server", name, SessionKey, 0, 0, 4000);

			outgoing = "What is it?";
			os.println(sc.encrypt_msg(outgoing));
			Log.log("SC Send: " + "What is it?", 2);

			incomming = is.readLine();
			if (incomming == null) {
				this.clientSocket.close();
				Log.log("Error (11)", 2);
				is.close();
				os.close();
				return;
			}
			incomming = sc.decrypt_msg(incomming);

			if (incomming == null) {
				Log.log("Error (12)", 2);
				is.close();
				os.close();
				return;
			}

			// =============================================== START OF REGISTER REQUEST
			if (incomming.equals("I want to register")) {
				Log.log("SC Receive: " + "I want to register", 2);

				outgoing = sc.encrypt_msg("What is your PIN?");

				os.println(outgoing);

				Log.log("SC Send: " + "What is your PIN?", 2);

				incomming = is.readLine();
				if (incomming == null) {
					this.clientSocket.close();
					Log.log("Error (13)", 2);
					is.close();
					os.close();
					return;
				}
				incomming = sc.decrypt_msg(incomming);

				if (incomming == null) {
					Log.log("Error (14)", 2);
					is.close();
					os.close();
					return;
				}

				Log.log("SC Received: " + "PIN: " + incomming, 2);

				String PIN = incomming;
				String regCode = this.server.add_unreg(name, PIN, other_public);

				Log.log("Server produced regcode: " + regCode, 2);

				if (regCode == null) {
					Log.log("Error (15)", 2);
					is.close();
					os.close();
					return;
				}
				os.println(sc.encrypt_msg(regCode));

				Log.log("SC Sent: " + "RegCode: " + regCode, 2);

			} // =============================================== END OF REGISTER REQUEST
				// ==================================================== START OF OTP REQUEST
			if (incomming.equals("I want an OTP")) {
				Log.log("SC Receive: " + "I want an OTP", 2);

				outgoing = sc.encrypt_msg("What is your PIN?");

				os.println(outgoing);

				Log.log("SC Send: " + "What is your PIN?", 2);

				incomming = is.readLine();
				if (incomming == null) {
					this.clientSocket.close();
					Log.log("Error (413)", 2);
					is.close();
					os.close();
					return;
				}
				incomming = sc.decrypt_msg(incomming);

				if (incomming == null) {
					Log.log("Error (414)", 2);
					is.close();
					os.close();
					return;
				}

				Log.log("SC Received: " + "PIN: " + incomming, 2);

				String PIN = incomming;
				String OTP = this.server.get_OTP(name, PIN, other_public);

				if (OTP == null) {
					Log.log("Error (415)", 2);
					is.close();
					os.close();
					return;
				}
				os.println(sc.encrypt_msg(OTP));

				Log.log("SC Sent: " + "OTP: " + OTP, 2);

			}
			// ====================================================================== START
			// OTP CHECK
			if (incomming.equals("I want an OTP Check")) {
				Log.log("SC Receive: " + "I want an OTP Check", 2);

				outgoing = sc.encrypt_msg("What is the OTP?");

				os.println(outgoing);
				Log.log("SC Send: " + "What is the OTP?", 2);

				incomming = is.readLine();
				if (incomming == null) {
					this.clientSocket.close();
					Log.log("Error (413)", 2);
					is.close();
					os.close();
					return;
				}
				incomming = sc.decrypt_msg(incomming);

				if (incomming == null) {
					Log.log("Error (414)", 2);
					is.close();
					os.close();
					return;
				}

				Log.log("SC Received: " + "OTP: " + incomming, 2);

				String OTP = incomming;

				/////////////////////
				outgoing = sc.encrypt_msg("What is the Name?");

				os.println(outgoing);

				Log.log("SC Send: " + "What is the Name?", 2);

				incomming = is.readLine();
				if (incomming == null) {
					this.clientSocket.close();
					Log.log("Error (413)", 2);
					is.close();
					os.close();
					return;
				}
				incomming = sc.decrypt_msg(incomming);

				if (incomming == null) {
					Log.log("Error (414)", 2);
					is.close();
					os.close();
					return;
				}

				Log.log("SC Received: " + "Name: " + incomming, 2);

				String Name = incomming;

				String result = this.server.check_OTP(Name, OTP, other_public);

				if (result == null) {
					Log.log("Error (415)", 2);
					is.close();
					os.close();
					return;
				}
				os.println(sc.encrypt_msg(result));

				Log.log("SC Sent: " + "Result: " + OTP, 2);

			} else {
				return;
			}

			// clean up when done
			is.close();
			os.close();
			clientSocket.close();

		} catch (IOException e) {
			Log.log("Error (G)", 2);
			return;
		}
	}

}
