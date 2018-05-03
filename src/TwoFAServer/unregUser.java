package TwoFAServer;

import java.io.Serializable;
import java.security.PublicKey;

class unregUser implements Serializable {

	private static final long serialVersionUID = 1L;
	private String name;
	private String regCode;
	private String pin;
	private PublicKey publicKey;

	unregUser(String name) {
		this.name = name;
	}

	unregUser(String name, String regCode, String pin, PublicKey publicKey) {
		super();
		this.name = name;
		this.regCode = regCode;
		this.pin = pin;
		this.publicKey = publicKey;
	}

	public boolean equals(Object other) {

		if (((unregUser) other).name.equals(this.name) == false)
			return false;

		return true;
	}

	public String toString() {
		return "Name: " + this.name + " RegCode: " + this.regCode + "PIN: " + this.pin;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getRegCode() {
		return regCode;
	}

	public void setRegCode(String regCode) {
		this.regCode = regCode;
	}

	public String getPin() {
		return pin;
	}

	public void setPin(String pin) {
		this.pin = pin;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

}
