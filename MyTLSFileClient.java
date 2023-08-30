import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/*
 * Jesse O'Connor
 * 1534760
 */
public class MyTLSFileClient {
    public static void main(String args[]) {
        if (args.length < 3) {
            System.err.println("usage: MyTLSFileClient <hostname> <port> <file>");
            return;
        }
        
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(args[0], Integer.parseInt(args[1]));
            /**
             * set HTTPS-style checking of HostName
             * before the handshake commences
             */
            SSLParameters params = new SSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(params);

            socket.startHandshake();
            
            /* get the X509Certificate for this session */
            SSLSession sesh = socket.getSession();
            X509Certificate cert = (X509Certificate) sesh.getPeerCertificates()[0];

            /* extract the CommonName, and then compare */
            System.out.println("Certificate Name: " + getCommonName(cert));

            File file = new File("_" + args[2]);
            FileOutputStream fileWrite = new FileOutputStream(file);
            InputStream read = socket.getInputStream();
            byte[] buffer = new byte[1024];

            PrintWriter write = new PrintWriter(socket.getOutputStream(), true);
            write.println(args[2]);
            write.println(args[0]);

            int length = read.read(buffer);
            while (length != -1) {
                fileWrite.write(buffer, 0, length);
                length = read.read(buffer);
            }
            read.close();
            fileWrite.close();

        } catch (NumberFormatException | IOException e) {
            e.printStackTrace();
        }
    }

    static String getCommonName(X509Certificate cert) {
        String name = cert.getSubjectX500Principal().getName();
        String cn = null;
        
        try {
            LdapName ln = new LdapName(name);
        
            for (Rdn rdn : ln.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    cn = rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            e.printStackTrace();
        }
        return cn;
        
    }

}
