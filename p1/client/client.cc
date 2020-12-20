#include <openssl/rsa.h>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "client_args.h"
#include "client_commands.h"

using namespace std;

int main(int argc, char **argv) {
  // Parse the command-line arguments
  client_arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  // If we don't have the keyfile on disk, get the file from server.  Once we
  // have the file, load the server's key.
  if (!file_exists(args.keyfile)) {
    int sd = connect_to_server(args.server, args.port);
    client_key(sd, args.keyfile);
    close(sd);
  }
  RSA *pubkey = load_pub(args.keyfile.c_str());
  ContextManager pkr([&]() { RSA_free(pubkey); });

  // Connect to the server and perform the appropriate operation
  int sd = connect_to_server(args.server, args.port);
  ContextManager sdc([&]() { close(sd); });

  // Figure out which command was requested, and run it
  vector<string> cmds = {REQ_REG, REQ_BYE, REQ_SET, REQ_GET, REQ_ALL, REQ_SAV};
  decltype(client_reg) *funcs[] = {client_reg, client_bye, client_set,
                                   client_get, client_all, client_sav};
  for (size_t i = 0; i < cmds.size(); ++i) {
    if (args.command == cmds[i]) {
      funcs[i](sd, pubkey, args.username, args.userpass, args.arg1, args.arg2);
    }
  }
}
