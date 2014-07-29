

public class fcrypt {
        public static void main(String[] args){
        	// input format check
        	inputCheck(args);
        	// if encrypt module
            if(args[0].equals("-e")){
            	new Encrypt(args[1],args[2],args[3],args[4]);
            }
            // if decrypt modle
            else if(args[0].equals("-d")){
            	new Decrypt(args[1],args[2],args[3],args[4]);

            }
            // error argument
            else{
            	System.out.println("Usage Error: java fcrypt -e/-d destination_public_key_filename sender_private_key_filename input_plaintext_file output_ciphertext_file");
            }
           

       }
        
       private static void inputCheck(String[] args){
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
       }

}
