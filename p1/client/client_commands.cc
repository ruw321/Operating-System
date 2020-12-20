#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string>
#include <fstream>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "client_commands.h"

using namespace std;

/// Pad with \0 characters
///
/// @param v    The vector to pad
/// @param size The number of bytes to add
void pad0(vec &v, size_t size) {
  while (v.size() < size) {
    v.push_back('\0');
  }
}

/// client_key() writes a request for the server's key on a socket descriptor.
/// When it gets it, it writes it to a file.
///
/// @param sd      An open socket
/// @param keyfile The name of the file to which the key should be written
void client_key(int sd, const string &keyfile) {
  vec req = vec_from_string("KEY");
  pad0(req, LEN_RKBLOCK);
  if (!send_reliably(sd, req)) {
    cerr << "key request is not sent\n"; 
  }
  vec res = reliable_get_to_eof(sd);
  if (res.size() == 0) {
    cerr << "error reading\n";
  }
  if(!write_file(keyfile, reinterpret_cast<const char *>(res.data()), res.size())){
    cerr << "error on write()\n";
  }
}


/// client_request() helps to generate r_block and a_block and encrypts them.
/// send blocks to server on a socket descriptor
/// get a response and decrypt it and return to client
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param cmd     The command to request
/// @param msg     The message to send
vec client_request(int sd, RSA *pubkey, const vec &cmd, const vec &msg) {

  //generate aes_key and aes_context to encrypt
  vec a_key = create_aes_key();
  EVP_CIPHER_CTX *ctx = create_aes_context(a_key, true);

  //implement default r_block and a_block
  vec r_block = vec_from_string("");
  vec a_block = vec_from_string("");
  unsigned char request[256];

  //append encrypted msg to a_block
  //switch context to decrypting
  vec_append(a_block, aes_crypt_msg(ctx, msg));
  reset_aes_context(ctx, a_key, false);

  //generate aes_key 
  //append cmd, a_key, a_block_size to r_block
  vec_append(r_block, cmd);
  vec_append(r_block, a_key);
  vec_append(r_block, a_block.size());

  //encrypt r_block 
  //store into request[256] array
  int len = RSA_public_encrypt(128, r_block.data(), request, pubkey, RSA_PKCS1_OAEP_PADDING);
  if (len == -1) {
    cerr << "error encrypting\n";
    return vec_from_string("");
  }

  //send r_block and a_block to server
  if(!send_reliably(sd, vec(request, request + len))){
    cerr << "request r_block is not sent\n";
  }
  if(!send_reliably(sd, a_block)){
    cerr << "request a_block is not sent\n";
  }

  //get response from server and decrypt it
  vec response = aes_crypt_msg(ctx, reliable_get_to_eof(sd));

  //clear context and return response
  reclaim_aes_context(ctx);
  return response;
}

/// client_reg() sends the REG command to register a new user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_reg(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {

  if(user.length() > LEN_UNAME || pass.length() > LEN_PASS){
    cerr << RES_ERR_LOGIN << endl;
  }
  vec msg = vec_from_string("");
  vec_append(msg, user.length());
  vec_append(msg, user);
  vec_append(msg, pass.length());
  vec_append(msg, pass);
  vec response = client_request(sd, pubkey, vec_from_string("REG"), msg);
  cerr << string(response.data(), response.data() + response.size()) << endl;;
}

/// client_bye() writes a request for the server to exit.
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_bye(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  if(user.length() > LEN_UNAME || pass.length() > LEN_PASS){
    cerr << RES_ERR_LOGIN << endl;
  }
  vec msg = vec_from_string("");
  vec_append(msg, user.length());
  vec_append(msg, user);
  vec_append(msg, pass.length());
  vec_append(msg, pass);
  vec response = client_request(sd, pubkey, vec_from_string("BYE"), msg);
  cerr << string(response.data(), response.data() + response.size()) << endl;
}

/// client_sav() writes a request for the server to save its contents
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
void client_sav(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  if(user.length() > LEN_UNAME || pass.length() > LEN_PASS){
    cerr << RES_ERR_LOGIN << endl;
  }
  vec msg = vec_from_string("");
  vec_append(msg, user.length());
  vec_append(msg, user);
  vec_append(msg, pass.length());
  vec_append(msg, pass);
  vec response = client_request(sd, pubkey, vec_from_string("SAV"), msg);
  cerr << string(response.data(), response.data() + response.size()) << endl;
}

/// client_set() sends the SET command to set the content for a user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void client_set(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &setfile, const string &) {
  if(user.length() > LEN_UNAME || pass.length() > LEN_PASS || setfile.length() > LEN_CONTENT){
    cerr << RES_ERR_LOGIN << endl;
  }
  vec msg = vec_from_string("");
  vec content = load_entire_file(setfile);
  vec_append(msg, user.length());
  vec_append(msg, user);
  vec_append(msg, pass.length());
  vec_append(msg, pass);
  vec_append(msg, content.size());
  vec_append(msg, content);
  vec response = client_request(sd, pubkey, vec_from_string("SET"), msg);
  cerr << string(response.data(), response.data() + response.size()) << endl;;
}

/// client_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void client_get(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &getname, const string &) {
  if(user.length() > LEN_UNAME || pass.length() > LEN_PASS || getname.length() > LEN_UNAME){
    cerr << RES_ERR_LOGIN << endl;
  }
  vec msg = vec_from_string("");
  vec_append(msg, user.length());
  vec_append(msg, user);
  vec_append(msg, pass.length());
  vec_append(msg, pass);
  vec_append(msg, getname.length());
  vec_append(msg, getname);
  vec response = client_request(sd, pubkey, vec_from_string("GET"), msg);

  //if ok, writes user's content to file
  if (response.size() >= 2 && response[0] == 'O' && response[1] == 'K'){
    int a = *(int *)(response.data() + 2);
    vec in = vec(response.data() + 6, response.data() + 6 + a);
    string out = getname + ".file.dat";
    if(!write_file(out, reinterpret_cast<const char *>(in.data()), in.size())){
      cerr << "error on write()\n";
    }
    cerr << "OK" << endl;
  }
  else {
    cerr << string(response.data(), response.data() + response.size()) << endl;;
  }
}

/// client_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
/// @param allfile The file where the result should go
void client_all(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &allfile, const string &) {
  if(user.length() > LEN_UNAME || pass.length() > LEN_PASS){
    cerr << RES_ERR_LOGIN << endl;
  }
  vec msg = vec_from_string("");
  vec_append(msg, user.length());
  vec_append(msg, user);
  vec_append(msg, pass.length());
  vec_append(msg, pass);
  vec response = client_request(sd, pubkey, vec_from_string("ALL"), msg);

  //if ok, writes all users to allfile
  if (response.size() >= 2 && response[0] == 'O' && response[1] == 'K'){
    int a = *(int *)(response.data() + 2);
    string input = string(response.data() + 6, response.data() + 6 + a);
    ofstream outfile(allfile);
    outfile << input << endl;
    outfile.close();
    cerr << "OK" << endl;
  }
  else{
    cerr << string(response.data(), response.data() + response.size()) << endl;;
  }
}
