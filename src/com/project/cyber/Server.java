package com.project.cyber;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server {

	private static final String SERVER = "server";
	private static final String PUBLIC_KEY = ".pub";
	private static final String PRIVATE_KEY = ".prv";
	private static final String PREPEND_STRING = "gfhk2024:";
	private static final String HEX_FORMAT = "%02X";
	private static final String MD5 = "MD5";

	private static HashMap<String, ArrayList<MessageContent>> userMessages = new HashMap<>();
	private static Integer port;

	public static void main(String[] args) throws IOException {

		System.out.println(System.getProperty("java.runtime.version"));

		initializePortNumber(args);

		try (ServerSocket ss = new ServerSocket(port)) {
			System.out.println("Waiting for an incoming socket connection...");

			while (true) {

				try (Socket s = ss.accept();
						ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
						DataInputStream dis = new DataInputStream(s.getInputStream())) {

					communicateWithTheClient(dis, oos);

				} catch (IOException e) {
					System.err.println("Client closed its connection with the server...");
				}

			}
		} catch (IOException e) {
			System.err.println("Error creating the server socket...");
			e.getMessage();
		}
	}

	private static void communicateWithTheClient(DataInputStream dis, ObjectOutputStream oos) {
		String hexedId = receiveClientHexedMD5UserId(dis);
		sendClientUnreadMessages(hexedId, oos);
		receiveClientEncryptedMessage(dis);
	}

	private static void receiveClientEncryptedMessage(DataInputStream dis) {
		String base64Message = null;
		try {
			if ((base64Message = dis.readUTF()) != null) {
				String result = decryptionUtil(SERVER, base64Message);
				String userId;
				if (result.startsWith("a")) {
					result = result.substring(5);
					userId = "alice";
				} else {
					result = result.substring(3);
					userId = "bob";
				}

				String hashedId = convertUserIdToHashedMD5Id(userId);
				MessageContent c = new MessageContent(encryptionUtil(userId, result.getBytes()), new Date());

				ArrayList<MessageContent> content;
				if (userMessages.containsKey(hashedId)) {
					content = userMessages.get(hashedId);
				} else {
					content = new ArrayList<>();
				}
				content.add(c);
				userMessages.put(hashedId, content);
			}
		} catch (EOFException e) {
			System.out.println("End of the file reached...");
		} catch (IOException e) {
			System.out.println("Client closed its connection with the server...");
		}
	}

	private static void sendClientUnreadMessages(String hexedId, ObjectOutputStream oos) {
		try {
			if (userMessages.containsKey(hexedId) && userMessages.get(hexedId).size() > 0) {
				ArrayList<MessageContent> messages = userMessages.get(hexedId);
				System.out.println(
						"There are " + messages.size() + " unread messages for this client, sending them all..");
				oos.writeInt(messages.size());
				for (MessageContent content : messages) {
					oos.writeObject(content);
				}
				userMessages.remove(hexedId);
			} else {
				System.out.println("There are no messages that needs to be delivered to the client...");
				oos.writeInt(0);
			}
			oos.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static String receiveClientHexedMD5UserId(DataInputStream dis) {
		String hexedUserId = null;
		try {
			if ((hexedUserId = dis.readUTF()) != null) {
				System.out.println("User " + hexedUserId + " logged in successfully!!!");
			}
			return hexedUserId;
		} catch (IOException e) {
			System.out.println("Client closed its connection with the server...");
		}
		return null;
	}

	private static String convertUserIdToHashedMD5Id(String userId) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(MD5);
			byte[] byteDigest = messageDigest.digest(PREPEND_STRING.concat(userId).getBytes());

			StringBuilder hexBuilder = new StringBuilder();
			for (byte bd : byteDigest) {
				hexBuilder.append(String.format(HEX_FORMAT, bd));
			}

			return hexBuilder.toString();
		} catch (NoSuchAlgorithmException e) {
		}
		return null;
	}

	private static String encryptionUtil(String userId, byte[] byteMessage) {
		try {
			PublicKey pubKey = getPublicKey(userId);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] raw = cipher.doFinal(byteMessage);

			return Base64.getEncoder().encodeToString(raw);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static String decryptionUtil(String userId, String message) {
		try {
			PrivateKey prvKey = getPrivateKey(userId);

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, prvKey);
			byte[] stringBytes = cipher.doFinal(Base64.getDecoder().decode(message));

			return new String(stringBytes, "UTF8");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static PublicKey getPublicKey(String userId) {
		try {
			File f = new File(userId.concat(PUBLIC_KEY));
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(pubSpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static PrivateKey getPrivateKey(String userId) {
		try {
			File f = new File(userId.concat(PRIVATE_KEY));
			byte[] keyBytes = Files.readAllBytes(f.toPath());
			PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(prvSpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static void initializePortNumber(String[] args) {
		if (args.length != 1) {
			System.err.println("The length of the provided argument is incorrect!!!");
			System.out.println("Please provide correct argument that denotes port number for the server to run on...");
			System.exit(-1);
		}

		port = Integer.parseInt(args[0]);
	}

	public static class MessageContent implements Serializable {
		private static final long serialVersionUID = 9131511945077216480L;
		private String encryptedMessage;
		private Date unencryptedTimestamp;

		public MessageContent() {
		}

		public MessageContent(String message, Date timestamp) {
			this.encryptedMessage = message;
			this.unencryptedTimestamp = timestamp;
		}

		public String getEncryptedMessage() {
			return encryptedMessage;
		}

		public void setEncryptedMessage(String encryptedMessage) {
			this.encryptedMessage = encryptedMessage;
		}

		public Date getUnencryptedTimestamp() {
			return unencryptedTimestamp;
		}

		public void setUnencryptedTimestamp(Date unencryptedTimestamp) {
			this.unencryptedTimestamp = unencryptedTimestamp;
		}
	}
}
