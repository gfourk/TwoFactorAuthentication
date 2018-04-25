/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package TwoFAServer;

import crypto.HY457Certificate;
import java.io.Serializable;
import java.util.Date;

/**
 *
 * @author vvasil
 */
public class netClient implements Serializable{

    public String name;
    public String ip;
    public HY457Certificate cert;
    public Date create_date;
    public boolean isvalid;

    public netClient(){
        this.name = "";
        this.ip = "localhost";
        this.create_date = new Date(System.currentTimeMillis());
        this.isvalid = true;
    }

    public boolean equals(Object other){
        return this.name.equals(((netClient)other).name);
    }

    public String toString(){
        return "Name: "+this.name;
    }

}
