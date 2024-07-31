# Kerberos
Multi-threaded Kerberos Protocol Implementation
This project was developed as part of the Cyber Security course at The Open University of Israel. It implements a multi-threaded version of the Kerberos protocol to enable secure and encrypted communication between clients and servers.

--Features--
Client Registration: Supports new client registration and login with an existing password.
Authentication Server (KDC): Generates a symmetric key derived from the password (using a hash function) for client-server communication.
Session Key Creation: Generates a session key for encrypted communication between the client and the service server (ticket-based).
Secure Messaging: Facilitates encrypted communication between the client and the service server for sending and printing messages.

--Components--
Client
Authentication and Key Distribution Center (KDC)
Service Server

--Usage--
Register a new client or log in with an existing password.
Establish a symmetric key with the KDC for secure communication.
Create a session key for the client-service server interaction.
Send encrypted messages from the client to the service server and have them displayed on the service server.
