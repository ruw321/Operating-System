#include <string>

#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"

#include "server_commands.h"
#include "server_storage.h"

using namespace std;

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_all(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  
  int index = 0;
  vec response = vec_from_string("");

  int u = *(int *)(req.data() + index);
  string username(req.begin() + index + 4, req.begin() + index + u + 4);
  index += u + 4;

  int p = *(int *)(req.data() + index);
  string password(req.begin() + index + 4, req.begin() + index + p + 4);
  index += p + 4;

  vec_append(response, aes_crypt_msg(ctx, storage.get_all_users(username, password).second));
  if(!send_reliably(sd, response)){
    cerr << "response is not sent\n";
  }
  return false;
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_set(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  int index = 0;
  vec response = vec_from_string("");

  int u = *(int *)(req.data() + index);
  string username(req.begin() + index + 4, req.begin() + index + u + 4);
  index += u + 4;

  int p = *(int *)(req.data() + index);
  string password(req.begin() + index + 4, req.begin() + index + p + 4);
  index += p + 4;

  int c = *(int *)(req.data() + index);
  vec content = vec_from_string("");
  if( c != 0){
    vec_append(content, vec(req.begin() + index + 4, req.begin() + index + c + 4));
  }
  index += c + 4;

  vec_append(response, aes_crypt_msg(ctx, storage.set_user_data(username, password, content)));
  if(!send_reliably(sd, response)){
    cerr << "response is not sent\n";
  }
  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_get(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  int index = 0;
  vec response = vec_from_string("");

  int u = *(int *)(req.data() + index);
  string username(req.begin() + index + 4, req.begin() + index + u + 4);
  index += u + 4;

  int p = *(int *)(req.data() + index);
  string password(req.begin() + index + 4, req.begin() + index + p + 4);
  index += p + 4;

  int w = *(int *)(req.data() + index);
  string who(req.begin() + index + 4, req.begin() + index + w + 4);
  index += w + 4;

  vec_append(response, aes_crypt_msg(ctx, storage.get_user_data(username, password, who).second));
  if(!send_reliably(sd, response)){
    cerr << "response is not sent\n";
  }
  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_reg(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  int index = 0;
  vec response = vec_from_string("");

  int u = *(int *)(req.data() + index);
  string username(req.begin() + index + 4, req.begin() + index + u + 4);
  index += u + 4;

  int p = *(int *)(req.data() + index);
  string password(req.begin() + index + 4, req.begin() + index + p + 4);
  index += p + 4;

  if(!storage.add_user(username, password)){
    vec_append(response, aes_crypt_msg(ctx, vec_from_string(RES_ERR_USER_EXISTS)));
    if(!send_reliably(sd, response)){
      cerr << "response is not sent\n";
    }
    return false;
  }
  vec_append(response, aes_crypt_msg(ctx, vec_from_string(RES_OK)));
  if(!send_reliably(sd, response)){
    cerr << "response is not sent\n";
  }
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
void server_cmd_key(int sd, const vec &pubfile) {
  send_reliably(sd, pubfile);
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns true, to indicate that the server should stop, or false on an error
bool server_cmd_bye(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  int index = 0;
  vec response = vec_from_string("");

  int u = *(int *)(req.data() + index);
  string username(req.begin() + index + 4, req.begin() + index + u + 4);
  index += u + 4;

  int p = *(int *)(req.data() + index);
  string password(req.begin() + index + 4, req.begin() + index + p + 4);
  index += p + 4;

  if(!storage.auth(username, password)){
    vec_append(response, aes_crypt_msg(ctx, vec_from_string(RES_ERR_LOGIN)));
    if(!send_reliably(sd, response)){
      cerr << "response is not sent\n";
    }
    return false;
  }
  vec_append(response, aes_crypt_msg(ctx, vec_from_string(RES_OK)));
  if(!send_reliably(sd, response)){
    cerr << "response is not sent\n";
  }
  return true;
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_sav(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  int index = 0;
  vec response = vec_from_string("");

  int u = *(int *)(req.data() + index);
  string username(req.begin() + index + 4, req.begin() + index + u + 4);
  index += u + 4;

  int p = *(int *)(req.data() + index);
  string password(req.begin() + index + 4, req.begin() + index + p + 4);
  index += p + 4;

  if(!storage.auth(username, password)){
    vec_append(response, aes_crypt_msg(ctx, vec_from_string(RES_ERR_LOGIN)));
    if(!send_reliably(sd, response)){
      cerr << "response is not sent\n";
    }
    return false;
  }
  storage.persist();
  vec_append(response, aes_crypt_msg(ctx, vec_from_string(RES_OK)));
  if(!send_reliably(sd, response)){
    cerr << "response is not sent\n";
  }
  return false;
}
