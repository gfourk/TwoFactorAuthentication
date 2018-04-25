/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package TwoFAServer;

import java.io.Serializable;
import java.security.PublicKey;
import utils.*;

/**
 *
 * @author vvasil
 */
public class unregUser implements Serializable{
    public String name;
    public String regCode;
    public String PIN;
    public PublicKey public_key;
    
    public boolean equals(Object other){

        if(((unregUser)other).name.equals(this.name) == false) return false;
        
        return true;
    }

    public String toString(){
        return "Name: "+this.name+" RegCode: "+ this.regCode+"PIN: "+this.PIN;
    }



}


