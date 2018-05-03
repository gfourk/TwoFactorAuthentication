package TwoFAClient;

import TwoFAClientGUI.TwoFAClientFrame;

public class TwoFAClientMain { // NO_UCD (unused code)

	public static void main(String[] args) {

		// create a TWoFAClient class instance
		TwoFAClient client = new TwoFAClient();

		TwoFAClientFrame a = new TwoFAClientFrame(client);
		a.setVisible(true);

	}

}
