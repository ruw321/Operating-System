#include <iostream>
#include <openssl/rsa.h>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"

#include "server_args.h"
#include "server_parsing.h"
#include "server_storage.h"

using namespace std;

int main(int argc, char **argv) {
  // Parse the command-line arguments
  server_arg_t args;
  parse_args(argc, argv, args);
  if (args.usage) {
    usage(argv[0]);
    return 0;
  }

  // print the configuration
  cout << "Listening on port " << args.port << " using (key/data) = ("
       << args.keyfile << ", " << args.datafile << ")\n";

  // If the key files don't exist, create them and then load the private key.
  RSA *pri = init_RSA(args.keyfile);
  if (pri == nullptr) {
    return -1;
  }
  ContextManager r([&]() { RSA_free(pri); });

  // load the public key file contents
  auto pub = load_entire_file(args.keyfile + ".pub");
  if (pub.size() == 0) {
    return -1;
  }

  // If the data file exists, load the data into a Storage object.  Otherwise,
  // create an empty Storage object.
  Storage storage(args.datafile);
  if (!storage.load()) {
    return 0;
  }

  // Start listening for connections.
  int sd = create_server_socket(args.port);
  ContextManager csd([&]() { close(sd); });

  // On a connection, parse the message, then dispatch
  accept_client(sd,
                [&](int sd) { return serve_client(sd, pri, pub, storage); });

  // When accept_client returns, it means we received a BYE command, so shut
  // down the storage and close the server socket
  storage.shutdown();
  cerr << "Server terminated\n";
}
