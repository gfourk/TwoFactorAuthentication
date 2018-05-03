package TwoFANetworkClient;

import TwoFANetworkClientGUI.TwoFANetClientFrame;

public class TwoFANetClientMain { // NO_UCD (unused code)

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		TwoFANetClient client = new TwoFANetClient();

		TwoFANetClientFrame a = new TwoFANetClientFrame(client);
		a.setVisible(true);

	}

}
