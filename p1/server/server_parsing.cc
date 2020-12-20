#include <cstring>
#include <iostream>
#include <openssl/rsa.h>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_parsing.h"
#include "server_storage.h"

using namespace std;

///check the request block is k_block
bool is_key(vec &block) {
  if (block.size() != 256){ 
    return false;
  }
  if (block[0] == 'K' && block[1] == 'E' && block[2] == 'Y') {
    for(int i = 3 ; i < 256 ; i++){
      if(block[i] != '\0'){
        return false;
      }
    }
    return true;
  }
  return false;
}

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to send to the client
/// @param storage The Storage object with which clients interact
///
/// @returns true if the server should halt immediately, false otherwise
bool serve_client(int sd, RSA *pri, const vec &pub, Storage &storage) {

  //generate pre-block for rk_block and response message for a_block;
  //256 : len of rk_block
  //1048780 : maximum possible size of a_block
  unsigned char block1[256];
  unsigned char block2[1048780];
  unsigned char r_block[128];
  vec first_block = vec(block1, block1 + 256);
  vec second_block = vec(block2, block2 + 1048780);
  vec a_block = vec_from_string("");
  
  //read request
  if(reliable_get_to_eof_or_n(sd, first_block.begin(), LEN_RKBLOCK) < 0){
    cerr << "cannot read rk_block 256 bytes from client\n";
  }
  //check first block is k_block
  if (is_key(first_block)) {
    server_cmd_key(sd, pub);
    return false;
  }

  //decrypt r_block from client request
  int len = RSA_private_decrypt(256, first_block.data(), r_block, pri, RSA_PKCS1_OAEP_PADDING);
  if (len == -1) {
    cerr << "error decrypting\n";
    return false;
  }

  //command
  string cmd = string(r_block, r_block + 3);
  //aes_key
  vec aes_key = vec(r_block + 3, r_block + 51);
  //size of a_block
  int a_block_size = *(int *)(r_block + 51);

  //read request from given size of a_block
  EVP_CIPHER_CTX *aes_ctx = create_aes_context(aes_key, false);
  //check if a_block's size is as expected 
  if(reliable_get_to_eof_or_n(sd, second_block.begin(), a_block_size) < 0){
     reset_aes_context(aes_ctx, aes_key, true);
     send_reliably(sd, aes_crypt_msg(aes_ctx, vec_from_string(RES_ERR_MSG_FMT)));
     return false;
  }
  //decrypt request into a_block
  vec_append(a_block, aes_crypt_msg(aes_ctx, vec(second_block.begin(), second_block.begin() + a_block_size)));
  reset_aes_context(aes_ctx, aes_key, true);

  vector<string> cmds = {REQ_REG, REQ_BYE, REQ_SET, REQ_GET, REQ_ALL, REQ_SAV};
  decltype(server_cmd_reg) *funcs[] = {server_cmd_reg, server_cmd_bye, server_cmd_set,
                                   server_cmd_get, server_cmd_all, server_cmd_sav};

  for (size_t i = 0; i < cmds.size(); ++i) {
    if (cmd == cmds[i]) {
      return funcs[i](sd, storage, aes_ctx, a_block);
    }
  }

  //invalid command error
  vec response = vec_from_string("");
  vec_append(response, aes_crypt_msg(aes_ctx, vec_from_string(RES_ERR_INV_CMD)));
  send_reliably(sd, response);
  return false;
}
