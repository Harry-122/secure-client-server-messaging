package com.project.cyber;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		int port = 5678;

		ServerSocket ss = new ServerSocket(port);

		while(true) {
			System.out.println("Waiting incoming connection...");

			Socket s = ss.accept();

			DataInputStream dis = new DataInputStream(s.getInputStream());

			String x = null;

			try {
				while ((x = dis.readUTF()) != null) {

					System.out.println(x);

				}
			}
			catch(IOException e) {
				System.err.println("Client closed its connection.");
			}
		}
		
	}

}
