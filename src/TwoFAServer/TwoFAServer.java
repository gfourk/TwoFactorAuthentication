/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package TwoFAServer;

import crypto.AESKey;
import crypto.HY457Certificate;
import crypto.crypt;
import java.io.File;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import utils.utils;

/**
 *
 * @author vvasil
 */
public class TwoFAServer {

    public KeyPair kp;
    public String username;
    public String password;
    public boolean logged_in;
    public int port_number;
    public PublicKey cert_public_key = null;

   ArrayList<HY457Certificate> cert_list;
   ArrayList<unregUser> unreg_list;
   ArrayList<regUser> reg_list;
   ArrayList<netClient> client_list;

    public TwoFAServer(){
        this.cert_list = new ArrayList<HY457Certificate>();
        this.unreg_list = new ArrayList<unregUser>();
        this.reg_list = new ArrayList<regUser>();
        this.client_list = new ArrayList<netClient>();
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

            boolean result =  crypt.saveEncrypt(new File(username+".server"), this.pack_state() , new AESKey(password));
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
                return crypt.saveEncrypt(new File(this.username+".server"), state, new AESKey(this.password));
        }


        /**
         * packs the state of the client in a byte array to be saved in a file
         */
        private byte[] pack_state(){
            byte[] username_bytes = this.username.getBytes();
            String username_hex_str = utils.toHex(username_bytes);

            byte[] rsa_bytes = utils.objectToBytes(this.kp);
            String rsa_hex_str = utils.toHex(rsa_bytes);


            byte[] cert_list_bytes = utils.objectToBytes(this.cert_list);
            String cert_list_hex_str = utils.toHex(cert_list_bytes);

            byte[] unreg_list_bytes = utils.objectToBytes(this.unreg_list);
            String unreg_list_hex_str = utils.toHex(unreg_list_bytes);

            byte[] reg_list_bytes = utils.objectToBytes(this.reg_list);
            String reg_list_hex_str = utils.toHex(reg_list_bytes);

            byte[] client_list_bytes = utils.objectToBytes(this.client_list);
            String client_list_hex_str = utils.toHex(client_list_bytes);



            String res = username_hex_str +"    "
                        +rsa_hex_str +"    "
                        +cert_list_hex_str+"    "
                        +unreg_list_hex_str+"    "
                        +reg_list_hex_str+"     "
                        +client_list_hex_str+" ";

            byte[] data = res.getBytes();

            return data;
        }
        /**
         * unpacks the state from a byte array
         * @param data
         * @return true for success false for failure
         */
        private boolean unpack_state(byte[] data){

            if(data == null ) return false;

            String res = new String(data);

            StringTokenizer st = new StringTokenizer(res," ");

            String username_hex_str = null;
            String rsa_hex_str = null;
            String cert_list_hex_str = null;
            String unreg_list_hex_str = null;
            String reg_list_hex_str = null;
            String client_list_hex_str = null;

            if(st.hasMoreTokens())
                username_hex_str = st.nextToken();
            if(st.hasMoreTokens())
                rsa_hex_str = st.nextToken();
            if(st.hasMoreTokens())
                cert_list_hex_str = st.nextToken();
            if(st.hasMoreTokens())
                unreg_list_hex_str = st.nextToken();
            if(st.hasMoreTokens())
                reg_list_hex_str = st.nextToken();
            if(st.hasMoreTokens())
                client_list_hex_str = st.nextToken();
            else return false;

            byte[] username_bytes = utils.toByte(username_hex_str);
            byte[] rsa_bytes = utils.toByte(rsa_hex_str);
            byte[] cert_list_bytes = utils.toByte(cert_list_hex_str);
            byte[] unreg_list_bytes = utils.toByte(unreg_list_hex_str);
            byte[] reg_list_bytes = utils.toByte(reg_list_hex_str);
            byte[] client_list_bytes = utils.toByte(client_list_hex_str);

            
            this.username = new String(username_bytes);
            this.kp = (KeyPair)utils.bytesToObject(rsa_bytes);
            this.cert_list = (ArrayList)utils.bytesToObject(cert_list_bytes);
            this.unreg_list = (ArrayList)utils.bytesToObject(unreg_list_bytes);
            this.reg_list = (ArrayList)utils.bytesToObject(reg_list_bytes);
            this.client_list = (ArrayList)utils.bytesToObject(client_list_bytes);

            return true;
    }

        /**
         * saves the public key in the file
         * @param file
         * @return
         */
    public boolean save_public_key(File file) {
        return utils.save(file, utils.objectToBytes(this.kp.getPublic()));
    }

    /**
     * loads the public key to be usedfor a cert for a file
     * @param file
     * @return
     */
    public boolean load_cert_public_key(File file) {
        
        byte[] loaded = utils.load(file);
        if(loaded == null) { this.cert_public_key = null; return false;}
        try{
        this.cert_public_key = (PublicKey) utils.bytesToObject(loaded);
        }catch(Exception e) {this.cert_public_key = null; return false;}
        return true;
    }

    /**
     * Creates a cert and saves it in the file provided
     * also stores it internally
     * @param text
     */
    public boolean create_cert(String name, File file) {

        // first check the name
        if(crypt.username_ok(name) == false ) return false;

        // now check to see if we have allready issued a cert for this name
        netClient nt = new netClient();
        nt.name = name;
        if(this.client_list.contains(nt)) return false;


        HY457Certificate cert = null;
        try {
            cert = new HY457Certificate(name, "2FAServer", this.kp.getPrivate(), this.cert_public_key);
        } catch (Exception ex) {
            return false;
        }
        // save the cert to a file
        byte[] cert_bytes = utils.objectToBytes(cert);
        utils.save(file, cert_bytes);

        // add the certificate to the netClient object
        nt.cert = cert;
        // add the new netClient to the list
        this.client_list.add(nt);
        return true;

    }

    /**
     * registers a user if he exists
     * @param name
     * @param code
     * @return
     */
    public boolean register_user(String name,String code){

        // first ceck to see if the user is allready registered
        regUser temp = new regUser();
        temp.name = name;
        if(this.reg_list.contains(temp)) return false;

        // now try to find the user in the unregistered list
        Iterator<unregUser> it = this.unreg_list.iterator();
        unregUser unreg = null;
        boolean found = false;

        while(it.hasNext()){
            unreg = it.next();
            if(unreg.name.equals(name) && unreg.regCode.equals(code)){
                found = true;
                break;
            }
        }
        if(found == true){
            regUser reg = new regUser();
            reg.name = unreg.name;
            reg.public_key = unreg.public_key;
            reg.PIN = unreg.PIN;
            reg.creationDate = new Date(System.currentTimeMillis());
            reg.isvalid = true;
            reg.last_OTP = null;
            reg.last_OTP_time = null;
            reg.tries = 0;

            this.reg_list.add(reg);
            this.unreg_list.remove(unreg);
            return true;
        }
        
        return false;
    }

    /**
     *
     * @param name
     * @param PIN
     * @param publicKey
     * @return
     */
    public String add_unreg(String name,String PIN,PublicKey publicKey){

        if(crypt.PIN_ok(PIN) == false) return null;

        // first check to see if the user is allready registered as a regUser
        regUser temp = new regUser();
        temp.name = name;
        if(this.reg_list.contains(temp)) return null;

        // now try to find the user in the unregistered list
        unregUser us = new unregUser();
        us.name = name;
        if(this.unreg_list.contains(us)) return null;

        // if we have not returnes by now, add the unregistered user

        unregUser new_user = new unregUser();
        new_user.PIN = PIN;
        new_user.name = name;
        new_user.public_key = publicKey;
        new_user.regCode = utils.toHex(utils.copy(utils.long_to_bytes(new SecureRandom().nextLong()),9,5));

        // after creating return null if allready found
        if(this.unreg_list.contains(new_user)) return null;
        // if not found then insert
        this.unreg_list.add(new_user);

        return new_user.regCode;
    }

    /**
     *
     * @param name
     * @param PIN
     * @param publicKey
     * @return
     */
    public String get_OTP(String name,String PIN,PublicKey publicKey){
        
        regUser user = new regUser();
        user.name = name;

        // if the user exists and is registered
        if(this.reg_list.contains(user)){

            user = this.reg_list.get(this.reg_list.indexOf(user));
            // check the PIN
            if(user.PIN.equals(PIN) == false) return null;
            String otp =  utils.toHex(utils.copy(utils.long_to_bytes(new SecureRandom().nextLong()),9,5));
            user.last_OTP = otp;
            user.last_OTP_time = new Date(System.currentTimeMillis());
            return otp;
        } else
            return null;
    }

    public String check_OTP(String name,String OTP ,PublicKey publicKey){
        
        regUser user = new regUser();
        user.name = name;
        // if the user exists and is registered
        if(this.reg_list.contains(user) ){
            //System.out.println("list containts user");
            user = this.reg_list.get(this.reg_list.indexOf(user));

            if(this.find_by_public(publicKey) == false)  { user.tries++; return "FAIL"; }

            System.out.println("2");
            if(user.isvalid == false)  { user.tries++; return "FAIL"; }
            System.out.println("3");
            if(user.last_OTP == null)  { user.tries++; return "FAIL"; }
            System.out.println("4");
            if(user.tries >= 3)  { user.tries++; user.isvalid = false; return "FAIL"; }
            System.out.println("5");
            if(user.last_OTP.equals(OTP) == false) { user.tries++; return "FAIL"; }
            if ((new Date(System.currentTimeMillis()) ).getTime() - user.last_OTP_time.getTime() > 60000){ user.tries++; return "FAIL"; }
            user.tries = 0;
            user.last_OTP = null;
            return "PASS";

        } else { user.tries++; return "FAIL"; }

    }

    private boolean find_by_public(PublicKey pk){
        Iterator<netClient> it = this.client_list.iterator();

        while(it.hasNext()){
            if(utils.compare(it.next().cert.getPublicKey().getEncoded(),pk.getEncoded()) == true)
                return true;
        }
        return false;

    }

    public String print_all(){

        String ret = "";

        Iterator<unregUser> it1 = this.unreg_list.iterator();
        Iterator<regUser> it2 = this.reg_list.iterator();
       

        ret+= "UNREGISTERED USERS:"+"\n";
        ret+="----------------------------------------------------\n";
        while(it1.hasNext()) {
            ret+=it1.next()+"\n";
        }
        ret+="\n";

        ret+= "REGISTERED USERS:"+"\n";
        ret+="----------------------------------------------------\n";
        while(it2.hasNext()) {
            ret+=it2.next()+"\n";
        }
        if(this.client_list != null){
        Iterator<netClient> it3 = this.client_list.iterator();
        ret+="\n";
        ret+= "CERTIFIED:"+"\n";
        ret+="----------------------------------------------------\n";
        while(it3.hasNext()) {
            ret+=it3.next()+"\n";
        }
        }


        return ret;



    }





}
