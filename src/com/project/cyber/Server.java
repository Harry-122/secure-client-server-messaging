package com.project.cyber;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server {

	public static void main(String[] args) throws IOException {
		
		System.out.println(System.getProperty("java.runtime.version"));

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

					String base64Message = null;
					try {
						while ((base64Message = dis.readUTF()) != null) {							
							File f = new File("server.prv");
							byte[] keyBytes = Files.readAllBytes(f.toPath());
							PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
							KeyFactory kf = KeyFactory.getInstance("RSA");
							PrivateKey prvKey = kf.generatePrivate(prvSpec);

							Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
							cipher.init(Cipher.DECRYPT_MODE, prvKey);
							byte[] stringBytes = cipher.doFinal(Base64.getDecoder().decode(base64Message));
							String result = new String(stringBytes, "UTF8");
							System.out.println(result);
						}
					} catch (EOFException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
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
