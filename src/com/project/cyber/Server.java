package com.project.cyber;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

	public static void main(String[] args) throws IOException {

		if (args.length != 1) {
			System.out.println("The length of the provided argument is incorrect!!!");
			System.out.println("Please provide correct argument that denotes port number for the server to run on...");
			return;
		}

		Integer port = Integer.parseInt(args[0]);

		try (ServerSocket ss = new ServerSocket(port)) {
			System.out.println("Waiting incoming connection...");

			while (true) {

				try (Socket s = ss.accept();
						DataOutputStream dos = new DataOutputStream(s.getOutputStream());
						DataInputStream dis = new DataInputStream(s.getInputStream())) {

					String message;
					try {
						while ((message = dis.readUTF()) != null) {
							System.out.println(message);
							dos.writeUTF(message.toUpperCase());
						}
					} catch (EOFException e) {
						System.out.println("End of the file reached.");
					}

				} catch (IOException e) {
					// IOException is thrown when the client closes its connection
					System.err.println("Client closed its connection.");
				}

			}
		} catch (IOException e) {
			System.err.println("Error creating the server socket.");
			e.getMessage();
		}

	}

}
