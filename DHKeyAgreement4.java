import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DHKeyAgreement4 {
    public static void main(String[] args) throws Exception {
            
            System.out.println("Generate key pair 1");
            KeyPairGenerator keyPairGen1 = KeyPairGenerator.getInstance("DH");
            keyPairGen1.initialize(2048);
            KeyPair keyPair1 = keyPairGen1.generateKeyPair();
            byte[] encodedKey1 = keyPair1.getPublic().getEncoded();

            DHParameterSpec sharedSecret = ((DHPublicKey)keyPair1.getPublic()).getParams();

            System.out.println("Generate key pair 2");
            KeyPairGenerator keyPairGen2 = KeyPairGenerator.getInstance("DH");
            keyPairGen2.initialize(sharedSecret);
            KeyPair keyPair2 = keyPairGen2.generateKeyPair();
            byte[] encodedKey2 = keyPair2.getPublic().getEncoded();


            System.out.println("Generate key pair 3");
            KeyPairGenerator keyPairGen3 = KeyPairGenerator.getInstance("DH");
            keyPairGen3.initialize(sharedSecret);
            KeyPair keyPair3 = keyPairGen3.generateKeyPair();
            byte[] encodedKey3 = keyPair3.getPublic().getEncoded();

            System.out.println("Generate key pair 4");
            KeyPairGenerator keyPairGen4 = KeyPairGenerator.getInstance("DH");
            keyPairGen4.initialize(sharedSecret);
            KeyPair keyPair4 = keyPairGen4.generateKeyPair();
            byte[] encodedKey4 = keyPair4.getPublic().getEncoded();

            System.out.println("Initialise key agreement 1");
            KeyAgreement keyAgree1 = KeyAgreement.getInstance("DH");
            keyAgree1.init(keyPair1.getPrivate());
        
            System.out.println("Initialise key agreement 2");
            KeyAgreement keyAgree2 = KeyAgreement.getInstance("DH");
            keyAgree2.init(keyPair2.getPrivate());
        
            System.out.println("Initialise key agreement 3");
            KeyAgreement keyAgree3 = KeyAgreement.getInstance("DH");
            keyAgree3.init(keyPair3.getPrivate());

            System.out.println("Initialise key agreement 4");
            KeyAgreement keyAgree4 = KeyAgreement.getInstance("DH");
            keyAgree4.init(keyPair4.getPrivate());

            KeyFactory theKeyFactory = KeyFactory.getInstance("DH");
            PublicKey decodedKey1 = theKeyFactory.generatePublic(new X509EncodedKeySpec(encodedKey1));
            PublicKey decodedKey2 = theKeyFactory.generatePublic(new X509EncodedKeySpec(encodedKey2));
            PublicKey decodedKey3 = theKeyFactory.generatePublic(new X509EncodedKeySpec(encodedKey3));
            Key decodedKey4 = theKeyFactory.generatePublic(new X509EncodedKeySpec(encodedKey4));
            
            Key oneToFour = keyAgree1.doPhase(decodedKey4, false);
            
            Key twoToOne = keyAgree2.doPhase(decodedKey1, false);

            Key threeToTwo = keyAgree3.doPhase(decodedKey2, false);

            Key fourToThree = keyAgree4.doPhase(decodedKey3, false);

            Key oneToFour2 = keyAgree1.doPhase(fourToThree, false);

            Key twoToOne2 = keyAgree2.doPhase(oneToFour, false);

            Key threeToTwo2 = keyAgree3.doPhase(twoToOne, false);

            Key fourToThree2 = keyAgree4.doPhase(threeToTwo, false);

            keyAgree1.doPhase(fourToThree2, true);

            keyAgree2.doPhase(oneToFour2, true);

            keyAgree3.doPhase(twoToOne2, true);

            keyAgree4.doPhase(threeToTwo2, true);

            byte[] sharedSecret1 = keyAgree1.generateSecret();
            System.out.println("Shared secret 1: " + toHexString(sharedSecret1));
            byte[] sharedSecret2 = keyAgree2.generateSecret();
            System.out.println("Shared secret 2: " + toHexString(sharedSecret2));
            byte[] sharedSecret3 = keyAgree3.generateSecret();
            System.out.println("Shared secret 3: " + toHexString(sharedSecret3));
            byte[] sharedSecret4 = keyAgree4.generateSecret();
            System.out.println("Shared secret 4: " + toHexString(sharedSecret4));

            if (!java.util.Arrays.equals(sharedSecret1, sharedSecret2)) {
                throw new Exception("Shared secrets 1 and 2 are different");
            }
            System.out.println("Shared secrets 1 and 2 are the same");

            if (!java.util.Arrays.equals(sharedSecret2, sharedSecret3)) {
                throw new Exception("Shared secrets 2 and 3 are different");
            }
            System.out.println("Shared secrets 2 and 3 are the same");

            if (!java.util.Arrays.equals(sharedSecret3, sharedSecret4)) {
                throw new Exception("Shared secrets 3 and 4 are different");
            }
            System.out.println("Shared secrets 3 and 4 are the same");
        }

        /*
        * Converts a byte to hex digit and writes to the supplied buffer
        */
        private static void byte2hex(byte b, StringBuffer buf) {
            char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
            int high = ((b & 0xf0) >> 4);
            int low = (b & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
        }
        /*
        * Converts a byte array to hex string
        */
        private static String toHexString(byte[] block) {
            StringBuffer buf = new StringBuffer();
            int len = block.length;
            for (int i = 0; i < len; i++) {
                byte2hex(block[i], buf);
                if (i < len-1) {
                    buf.append(":");
                }
            }
            return buf.toString();
        }
    }