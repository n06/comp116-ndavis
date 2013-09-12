Assignment 1: PCAP Forensics
============================

Set1.pcap
---------

1. Total number of packets: 276
2. The protocol used to transfer files was FTP (File Transfer Protocol
3. FTP is not able to encrypt its traffic, and therefore all data sent
   over FTP is in plain text
4. The secure alternative to FTP is FTPS (FTP Secure) which adds TLS/SSL
   to the protocol in order to encrypt traffic
5. The IP address of the server is: 67.23.79.113. As of this writing,
   the server is still active and accepting incoming FTP connections
6. The username used to access the server is: stokerj, and the password
   is: w00tfu!
7. Three files were uploaded to the server over FTP
8. The files were: code.rtf, secret.pdf, and acb.jpg
9. The files can be found within this directory for inspection

Set2.pcap
---------

10. Total number of packets: 74566
11. 1,2,3,4,5,6,7
12. In wireshark, I did a string search for "pass" and enumerated
    through all the packets that matched the search. In some cases the
user/pass combos were in the details, and in other cases I follwed the
tcp stream for more info.
13. The protocols on which usernames/passwords were found are POP and
    TELNET
14. 3 out of the 5 username/password combinations were succesful.
15. I verified the username/password combinations by following the tcp
    stream and checking to see if the server returned unauthorized or
not.
16. We do not have permission to break into the servers in question, and
    therefore any unauthorized access is unethical and potentially
illegal.
17. Use a VPN, do not use unencrypted protocols, and NEVER use the
    defcon wifi. Also, now that these accounts are compromised change
the password of any account that shares a password with the one
compromised.
18. 

