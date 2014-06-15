
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.*;

public class fcrypt {
        public static void main(String[] args){
            // input check
            if(args.length<5 ){
              System.out.println("Args length: " + args.length);
              System.out.println("Usage Error: java fcrypt [-e/-d] destination_public_key_filename sender_private_key_filename input_plaintext_file output_ciphertext_file");
              System.exit(0);;
            }
            if(!args[0].equals("-e") && !args[0].equals("-d")){
              System.out.println("Args[0] error");
              System.out.println("args[0]: " + args[0]);
              System.exit(0);;
            }
            // 
            fcrypt instance = new fcrypt();
            if(args[0].equals("-e")){
              try{
                instance.encrypt(Arrays.copyOfRange(args,1,5));
              }
              catch(Exception e){
                System.out.println(e.getMessage());
              }
            }
            else if(args[0].equals("-d")){


            }else{


            }


        }

	public void encrypt(String[] args) throws Exception {

		String public_key_filename, private_key_filename, plaintext_file,output_file;
                // input error halding
                if(isInputError(args))
                    System.exit(0);
		// Public, private and signature instances
		Cipher publicChiper = Cipher.getInstance("RSA");
		Cipher secCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		Signature sig = Signature.getInstance("SHA512withRSA");
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		Key aesKey;
		PKCS8EncodedKeySpec privateSpec;
		X509EncodedKeySpec publicSpec;
		PrivateKey prvKey;
		PublicKey pubKey;
		
		// byte representation of parameters and IV
		byte[] iv, cipherText, publicKey, plainText, privateKey, signature, aesKeyEncyrpted;

		// Encrypting files
                // public file name
		public_key_filename = args[0];
                 // private file name
		private_key_filename = args[1];
		// plaintext_file name
		plaintext_file = args[2];
                // output_file name
                output_file=args[3];
				
		
		
	
		// Symmetric (AES) key generation
		KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
		aesKey = aesKeyGen.generateKey();
		// read bytes from the file
		plainText = readByteFromFile(new File(plaintext_file));
		// setup IV key with random data and encrypt the file using AES key.
		secCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		iv = secCipher.getIV();
		cipherText = secCipher.doFinal(plainText);
		
		privateKey = readByteFromFile(new File(private_key_filename));
		publicKey = readByteFromFile(new File(public_key_filename));
		privateSpec = new PKCS8EncodedKeySpec(privateKey);
		publicSpec = new X509EncodedKeySpec(publicKey);
		prvKey = rsaKeyFactory.generatePrivate(privateSpec);
		pubKey = rsaKeyFactory.generatePublic(publicSpec);

		publicChiper.init(Cipher.WRAP_MODE, pubKey);
		aesKeyEncyrpted = publicChiper.wrap(aesKey);

		sig.initSign(prvKey);
		sig.update(iv);
		sig.update(cipherText);
		sig.update(aesKeyEncyrpted);
		signature = sig.sign();
			
		/**
			If you experiment with differet files, you will notice that the size
			of the signature stays the same, but the size of the ciphertext increases
			as the size of the plain text increases.
		**/
		System.out.println("Signature in HEX");
		for (byte b : signature){
			System.out.print(String.format("%02X ", b));
		}
		System.out.println();
		System.out.println();
		System.out.println("Ciphter Text");
		for (byte b : cipherText){
			System.out.print(String.format("%02X ", b));
		}
		System.out.println();
                writeByteToFile(new File(output_file),cipherText);
	}
        private static boolean isInputError(String[] args){
          int arg_len=4;
          if(args.length<arg_len){
            System.out.println("Input arguments less than 3, please try again.");
            return true;
          }
          for(int i=0;i<arg_len-1;i++){
            if(!new File(args[i]).isFile()){
              System.out.println("File: " + args[i] + " not exist or not a file");
              return true;
            }

          }

          return false;
        }

	// read bytes from a file
	private static byte[] readByteFromFile(File f) throws Exception {

		if (f.length() > Integer.MAX_VALUE)
			System.out.println("File is too large");

		byte[] buffer = new byte[(int) f.length()];
		InputStream ios = new FileInputStream(f);;
		DataInputStream dis = new DataInputStream(ios);
		dis.readFully(buffer);
		dis.close();
		ios.close();

		return buffer;
	}
        private static boolean writeByteToFile(File f,byte[] bytes) throws Exception{
         FileOutputStream stream = new FileOutputStream(f);
         try{
            stream.write(bytes);
        }finally{
          stream.close();
        }
         return true; 
        }
}
