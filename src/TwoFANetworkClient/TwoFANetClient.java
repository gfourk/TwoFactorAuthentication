package TwoFANetworkClient;

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
import java.util.logging.Level;
import java.util.logging.Logger;
import utils.*;

public class TwoFANetClient {
	
    private KeyPair kp;
    String username;
    String password;
    public boolean logged_in;
    public boolean server_cert_loaded;
    PublicKey server_key;


    public String check_OTP(String OTP,String name, String port,String host){

            int port_number;
            try{
            port_number = Integer.parseInt(port);
            } catch(Exception e){Log.log("Error (60)",3); return null;}

            Socket clientSocket = null;
	    PrintStream os = null;
	    DataInputStream is = null;

            try {
		// Try to open a socket on a given host and port
		clientSocket = new Socket(host, port_number);
		clientSocket.setSoTimeout(0);
		// Try to open input and output streams
                os = new PrintStream(clientSocket.getOutputStream());
                is = new DataInputStream(clientSocket.getInputStream());
	    } catch (UnknownHostException e) {
                Log.log("Error (61)",3);
	    	return null;
	    } catch (IOException e) {
                Log.log("Error (62)",3);
	    	return null;
	    }

            if (clientSocket == null || os == null || is == null){
                Log.log("Error (63)",3);
                return null;
            }

	    String response = null;

            // ============================================================================= #1 out
            // create the first message ( R - <user name> - user's Public Key )
            int nonce = Math.abs(new SecureRandom().nextInt());
            String msg = "";
            msg+=nonce;
            msg += "-";
            msg +=this.username;
            msg+= "-";
            msg+= utils.toHex(utils.objectToBytes(this.kp.getPublic()));

            try {
            // encrypt the first msg with the servers public key
            msg = utils.toHex(crypt.RSAEncrypt(msg.getBytes(), this.server_key));
        } catch (Exception ex) {
            Log.log("Error (64)",3); return null;}

            // send the fisrt msg
            try{ this.wait(500); } catch (Exception e) {;}
            os.println(msg);
            Log.log("Sent: "+"<<Nonce,Name,PublicKey>>"+ "Nonce: "+nonce+" Name: "+this.username ,3);

          // ================================================================================ #2 in
           try {
                response = is.readLine();
           } catch (IOException e) {
               Log.log("Error (65)",3);
              return null;
           }
            try{
            response =new String(
                    crypt.RSADecrypt(
                    crypt.RSADecrypt(
                    utils.toByte(response), this.kp.getPrivate())
                    ,this.server_key));
            } catch (Exception e){Log.log("Error (66)",3); return null; }

            StringTokenizer st = new StringTokenizer(response,"-");

            long nonce_1 = 0;
            AESKey sessionKey = null;
            if(st.hasMoreTokens())
                nonce_1 = Long.parseLong(st.nextToken());
            if(st.hasMoreTokens())
                try{
                sessionKey = (AESKey) utils.bytesToObject(utils.toByte(st.nextToken()));
                } catch (Exception e){Log.log("Error (67)",3); return null; }
            else{
                Log.log("Error (68)",3); return null;
            }

            if(nonce_1 != nonce+1) {
                Log.log("Error (69)",3); return null;
            }
            Log.log("Received: <<Nonce+1,Session Key>> Nonce+1: "+nonce_1,3);

            //============================================================================= #3 out
                nonce = nonce+2;
                response = "" +nonce+"-"+utils.toHex(utils.objectToBytes(sessionKey));

                try{
                response = utils.toHex(
                        crypt.RSAEncrypt(
                        (crypt.RSAEncrypt(response.getBytes(), this.kp.getPrivate())),this.server_key));
                }
                catch(Exception e){Log.log("Error (610)",3); return null;}

                try{ this.wait(500); } catch (Exception e) {;}
                os.println(response);
                Log.log("Sent: <<Nonce+2,Session Key>> Nonce+2: "+nonce,3);

                // =================================================================== end of negotiations

                // ===================================================================

                // ================================================================ OTP Check REQUEST
                SC sc = new SC(this.username,"Server", sessionKey, 0, 0, 4000);

                try {
                    response = is.readLine();
                } catch (IOException e) {
                    Log.log("Error (611)",3);
                    return null;
                }

                try{ this.wait(500); } catch (Exception e) {;}
                response = sc.decrypt_msg(response);

                if(response.equals("What is it?") == false){
                    Log.log("Error (512)",3);
                    return null;
                }
                Log.log("SC Received: "+"What is it?", 3);

                response = "I want an OTP Check";

                response = sc.encrypt_msg(response);

                try{ this.wait(500); } catch (Exception e) {;}
                os.println(response);

                Log.log("SC Sent: "+"I want an OTP Check", 3);


                try {
                    response = is.readLine();
                } catch (IOException e) {
                    Log.log("Error (613)",3);
                    return null;
                }

                response = sc.decrypt_msg(response);

                if(response.equals("What is the OTP?") == false){
                    Log.log("Error (614)",3);
                    return null;
                }

                Log.log("SC Received: "+"What is the OTP?", 3);

                response = sc.encrypt_msg(OTP);
                try{ this.wait(500); } catch (Exception e) {;}
                os.println(response);

                Log.log("SC Sent: "+"OTP: "+OTP, 3);

                try {
                    response = is.readLine();
                } catch (IOException e) {
                    Log.log("Error (623)",3);
                    return null;
                }

                response = sc.decrypt_msg(response);

                if(response.equals("What is the Name?") == false){
                    Log.log("Error (624)",3);
                    return null;
                }

                Log.log("SC Received: "+"What is the Name?", 3);

                response = sc.encrypt_msg(name);
                try{ this.wait(500); } catch (Exception e) {;}
                os.println(response);

                Log.log("SC Sent: "+"Name: "+name, 3);


                try {
                    response = is.readLine();
                } catch (IOException e) {
                    Log.log("Error (625)",3);
                    return null;
                }

                response = sc.decrypt_msg(response);

                Log.log("SC Received: "+"OTP: "+response, 3);

            try { clientSocket.close(); }
            catch (IOException ex) { Log.log("Error (X)",1); return null;}

            return response;

    }



        /**
         * Loads a file with all its data
         * @param file
         * @param password
         * @return
         */
        public boolean load_file(File file,String password) {
            byte[] data = crypt.loadDecrypt(file, new AESKey(password));
            this.password = password;
            boolean result = this.unpack_state(data);
            this.logged_in = result;
            return result;
        }

        /**
         * creates file from the state
         * @param text
         * @param string
         * @return
         */
        public boolean create_file(String username, String password) {
            this.username = username;
            this.password = password;
            this.kp = crypt.getRSAKeyPair();

            boolean result =  crypt.saveEncrypt(new File(username+".netclient"), this.pack_state() , new AESKey(password));
            this.logged_in = result;
            return result;
        }

        /**
         * saves and exits
         * @return
         */
        public boolean save_and_exit(){

            if(this.logged_in == false)
                return false;

            byte[] state = this.pack_state();
            if(state == null)
                return false;
            else
                return crypt.saveEncrypt(new File(this.username+".client"), state, new AESKey(this.password));
        }

        /**
         * Loads the servers certificate
         * @param file
         * @return
         */
        public boolean load_server_cert(File file){

            byte[] cert_bytes = utils.load(file);
            if(cert_bytes == null) return false;
            HY457Certificate server_cert = null;
            try{
            server_cert = (HY457Certificate) utils.bytesToObject(cert_bytes);
            if(server_cert.check(server_cert.getPublicKey()) == false) return false;
            if(server_cert.getOwner().equals("2FAServer") == false ) return false;
            if(server_cert.getIssuer().equals("2FAServer") == false ) return false;
            } catch (Exception e){ return false; }

            this.server_cert_loaded = true;
            this.server_key = server_cert.getPublicKey();

            return true;

        }

        /**
         * packs the state of the client in a byte array to be saved in a file
         */
        private byte[] pack_state(){
            byte[] username_bytes = this.username.getBytes();
            String username_hex_str = utils.toHex(username_bytes);

            byte[] rsa_bytes = utils.objectToBytes(this.kp);
            String rsa_hex_str = utils.toHex(rsa_bytes);

            String res = username_hex_str + " " +rsa_hex_str;

            byte[] data = res.getBytes();

            return data;
        }

        /**
         * unpacks the state from a byte array
         * @param data
         * @return true for succes false for failure
         */
        private boolean unpack_state(byte[] data){

            if(data == null ) return false;

            String res = new String(data);

            StringTokenizer st = new StringTokenizer(res," ");

            String username_hex_str = null;
            String rsa_hex_str = null;

            if(st.hasMoreTokens())
                username_hex_str = st.nextToken();
            if(st.hasMoreTokens())
                rsa_hex_str = st.nextToken();
            else return false;

            byte[] username_bytes = utils.toByte(username_hex_str);
            byte[] rsa_bytes = utils.toByte(rsa_hex_str);

            this.username = new String(username_bytes);
            this.kp = (KeyPair)utils.bytesToObject(rsa_bytes);

            return true;
        }

    public boolean save_public_key(File file) {
        return utils.save(file, utils.objectToBytes(this.kp.getPublic()));
    }


}
