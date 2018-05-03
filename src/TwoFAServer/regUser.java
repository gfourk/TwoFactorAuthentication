package TwoFAServer;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;

class regUser implements Serializable {

	private static final long serialVersionUID = 1L;
	private String name;
	private PublicKey publicKey;
	private String pin;
	private Date creationDate;
	private boolean isvalid;
	private Date lastOTPTime;
	private String lastOTP;
	private int tries;

	regUser(String name) {
		this.name = name;
	}

	regUser(String name, PublicKey publicKey, String pin, Date creationDate, boolean isvalid, Date lastOTPTime,
			String lastOTP, int tries) {
		super();
		this.name = name;
		this.publicKey = publicKey;
		this.pin = pin;
		this.creationDate = creationDate;
		this.isvalid = isvalid;
		this.lastOTPTime = lastOTPTime;
		this.lastOTP = lastOTP;
		this.tries = tries;
	}

	public boolean equals(Object other) {

		if (this.name.equals(((regUser) other).name) == false)
			return false;

		else
			return true;
	}

	public String toString() {
		return "Name: " + this.name + " Valid: " + this.isvalid + " last OTP: " + this.lastOTP + " Tries: " + this.tries
				+ " PIN: " + this.pin;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public String getPin() {
		return pin;
	}

	public void setPin(String pin) {
		this.pin = pin;
	}

	public Date getCreationDate() {
		return creationDate;
	}

	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	public boolean isIsvalid() {
		return isvalid;
	}

	public void setIsvalid(boolean isvalid) {
		this.isvalid = isvalid;
	}

	public Date getLastOTPTime() {
		return lastOTPTime;
	}

	public void setLastOTPTime(Date lastOTPTime) {
		this.lastOTPTime = lastOTPTime;
	}

	public String getLastOTP() {
		return lastOTP;
	}

	public void setLastOTP(String lastOTP) {
		this.lastOTP = lastOTP;
	}

	public int getTries() {
		return tries;
	}

	public void setTries(int tries) {
		this.tries = tries;
	}

}
