package TwoFAServer;

import crypto.HY457Certificate;
import java.io.Serializable;

class netClient implements Serializable {

	private static final long serialVersionUID = 1L;
	String name;
	HY457Certificate cert;
	

	public netClient() {
		this.name = "";
	}

	public boolean equals(Object other) {
		return this.name.equals(((netClient) other).name);
	}

	public String toString() {
		return "Name: " + this.name;
	}

}
