/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package TwoFAServer;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;

/**
 *
 * @author vvasil
 */
public class regUser implements Serializable{
    public String name;
    public PublicKey public_key;
    public String PIN;
    public Date creationDate;
    public boolean isvalid;
    public Date last_OTP_time;
    public String last_OTP;
    public int tries;

    public boolean equals(Object other){
        if(this.name.equals(((regUser)other).name) == false) return false;

        else return true;
    }

    public String toString(){
        return "Name: "+this.name+" Valid: "+this.isvalid+" last OTP: "+this.last_OTP+" Tries: "+this.tries+" PIN: "+this.PIN;
    }
}
