package com.project.cyber;

import java.io.DataOutputStream;
import java.net.Socket;

public class Client {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String host = "localhost"; // hostname of server

		int port = 5678; // port of server

		try {
			Socket s = new Socket(host, port);

			DataOutputStream dos = new DataOutputStream(s.getOutputStream());

			dos.writeUTF("Hello World!");
			dos.writeUTF("Happy new year!");

		} catch (Exception e) {

			System.err.println("Cannot connect to server.");
		}
	}

}
