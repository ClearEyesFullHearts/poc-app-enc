# Application Layer Security

## Permanent Keys

### Server
`SK_SIG_ANON_CLAIM`: RSA (4096) secret key for message signature  
`MASTER_SK_ENC_AUTH`: Randomly generated key for eJWT encryption  

### Client
`PK_SIG_ANON_CLAIM`: RSA (4096) public key for signature verification  

## Session Keys
`EC_ENC_SERVER_[SK/PK]`: Server side one time EC key pair used to compute a shared secret (ECDH)  
`EC_ENC_CLIENT_[SK/PK]`: Client side one time EC key pair used to compute a shared secret (ECDH)  
`EC_SIG_CLIENT_[SK/PK]`: Client side temporary EC key pair used to sign client communication (ECDSA)  
`EC_SIG_SERVER_[SK/PK]`: Server side temporary EC key pair used to sign server communication (ECDSA)  
`SSK_ENC`: Computed shared secret key by `EC_ENC_[CLIENT/SERVER]_[SK/PK]` for messages encryption

## eJWT
Encrypted JWT-like used by the server for authentification and communication with the client. It is composed of 3 parts, header, body and a footer, encoded in base64url and separated by a dot.
### Body
The body is entirely encrypted using `MASTER_SK_ENC_AUTH`. It cannot be decrypted by the client. it contains:  
- The user's claim (anonymous or authenticated).
- The computed shared secret `SSK_ENC` that will be used to encrypt/decrypt the messages between server and client.
- The client temporary signature public key `EC_SIG_CLIENT_PK` used to verify the client's messages.
- The server temporary signature secret key `EC_SIG_SERVER_SK` used to sign the server's messages.
- An Issued AT claim (iat)
### Header
The header is the salt used to derive `MASTER_SK_ENC_AUTH` prepended to the IV used to encrypt the body in clear text (base64url encoded). It is used to decrypt the body.  
### Footer
The footer is the HMAC of the ciphertext, the salt, the iv and any additional data appropriate (base64url encoded). It is used to verify the integrity and authenticity of the eJWT.  

## Protocol

### Get anonymous claim
Clara is the client, Seb is the server.  
  
1. Clara generates `EC_ENC_CLIENT_[SK/PK]` and `EC_SIG_CLIENT_[SK/PK]`
2. Clara POST `EC_ENC_CLIENT_PK` and `EC_SIG_CLIENT_PK` to Seb
3. Seb generates `EC_ENC_SERVER_[SK/PK]` and `EC_SIG_SERVER_[SK/PK]`
4. Seb computes `SSK_ENC` with `EC_ENC_SERVER_SK` and `EC_ENC_CLIENT_PK`
5. Seb creates an eJWT containing `SSK_ENC` and `EC_SIG_CLIENT_PK` and `EC_SIG_SERVER_SK`
6. Seb sign the eJWT,  `EC_ENC_SERVER_PK` and `EC_SIG_SERVER_PK` with `SK_SIG_ANON_CLAIM`
7. Seb returns the eJWT, `EC_ENC_SERVER_PK`, `EC_SIG_SERVER_PK` and the signature to Clara
8. Clara verify the response signature with `PK_SIG_ANON_CLAIM`
9. Clara computes `SSK_ENC` with `EC_ENC_SERVER_PK` and `EC_ENC_CLIENT_SK` and stores it
10. Clara stores `EC_SIG_SERVER_PK`

From this point Clara has the shared secret in session and Seb will get it through the eJWT, so every communication from Clara to Seb will look like:
- Clara encrypt her request with the shared secret `SSK_ENC`
- Clara sign her encrypted request with `EC_SIG_CLIENT_SK`
- Clara sends the encrypted request and the signature with the session eJWT.
  
On its side Seb will:
- Check the integrity of the eJWT thanks to the HMAC
- Decrypt the eJWT, to get the shared secret (`SSK_ENC`), Clara's signature public key (`EC_SIG_CLIENT_PK`) and its own signature secret key `EC_SIG_SERVER_SK`
- Verify the integrity of Clara's encrypted request
- Decrypt the request with the shared secret
  
When its time for Seb to respond:
- Seb encrypt the response with the shared secret (`SSK_ENC`)
- Seb sign the encrypted response with its temporary signature key `EC_SIG_SERVER_SK`
- Seb sends the encrypted response and the signature to Clara
  
So Clara:
- Clara verify the integrity of the message with Seb's temporary signature key `EC_SIG_SERVER_PK`
- Clara decrypt the response with the shared secret (`SSK_ENC`)

### After that
- The time to live of an anonymous eJWT should be very short
- An anonymous eJWT should be used only once, through an API session or WAF rules
- The client and the user are 2 different things, the protocol authenticate the client but does nothing to identify the user
- The only thing you should be able to do with an anonymous eJWT is user authentication
- The authentication of the user itself depends of the API and should create a longer lived eJWT