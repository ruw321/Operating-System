# Assignment #1: Creating a Secure On-Line Service

The purpose of this assignment is to get you thinking about how to compose
different security concepts to create an on-line service with authentication and
encryption.

## Assignment Details

During the warm-up assignment, we reviewed many powerful system programming
techniques.  We saw how to load a file from disk as a byte stream, and how to
send byte streams to disk as new files.  We saw how to use RSA and AES
encryption.  We saw how to send bytes over the network and how to receive them.
In this assignment, we are going to start putting those ideas together to build
an on-line service.

As with any service, we will have two separate programs: a client and a server.
For now, the server will only handle authentication.  The server will manage a
"directory" of users.  Each user can store a single file of up to 1MB of data as
their "profile".

Our focus is on security, and we have two goals.  The first is to ensure that
users cannot make unauthorized accesses.  To that end, we will have a
registration mechanism by which users can get an account on the system.  A user
will have permission to read any other user's profile, and to get a list of all
user names.  A user will also have permission to change her/his own profile.

The second goal is to make sure that communications between the client and
server are secure.  Any intermediary who intercepts a transmission should not be
able to decipher it to figure out what is being communicated.

The final requirement of the service is that it has a rudimentary form of
persistence, wherein the entire directory gets saved to disk in response to
specific client requests.  This is not a great long-term strategy, but it will
be sufficient for now.

Note that the server will not be concurrent yet.  It need only handle one client
at a time.

## Getting Started

Your git repository contains a significant portion of the code for the final
solution to this assignment.  The `p1/common/` folder has variants of many of
the useful functions that we created for assignment 0.  The `p1/client/` folder
has code that is specific to the client, and the `p1/server/` folder has code
that is specific to the server.  You should be able to type `make` from the
`p1/` folder to build all of the code, and you should be able to run the basic
tests for the assignment by typing the following from the `p1` folder:

```bash
python3 tests/p1_authentication.py
```

Of course, none of the tests will pass yet.  You will probably see some errors,
and then the script will crash.  In the solutions folder you can find
executables that implement the client and server.  You can override the script
to use either of these (or both) like this:

```bash
python3 tests/p1_authentication.py CLIENT
python3 tests/p1_authentication.py SERVER
python3 tests/p1_authentication.py CLIENT SERVER
```

You can also see more about what the script is doing:

```bash
python3 tests/p1_authentication.py VERBOSE
```

The best way to understand the low-level details of how the client and server
are supposed to work is by reading the `common/protocol.h` file.  This file
documents the protocol for client/server interaction.  Note that the encryption
procedure we use is very carefully designed, and very easy to get wrong.  There
are two tricky parts:

* The first is that the client needs to put information into the right "blocks"
  of its message.  As you write your code, it will become apparent why we have
  defined the `rblock` as we have.  As a hint, you might want to consider how
  you would allocate a buffer for the `ablock` if you didn't know its size.
* The second is that AES encryption is very fickle.  When you AES-encrypt data,
  you must make sure to properly handle the last block.  You should not be using
  a file as a temporary storage place for the data you encrypt/decrypt.
  Consequently, you will need to redesign the AES encryption code from
  assignment 0.

## Tips and Reminders

The code that we provide makes use of a number of C++ features.  You should be
sure you understand the way we use `std::vector`.  In particular, you should
know the difference between `std::vector<unsigned char> v(1024)` and
`std::vector<unsigned char> v; v.reserve(1024)`.  Also, note that our use of
`std::vector` can introduce unnecessary copying, which should be optimized out
in an advanced implementation.  On the other hand, some copying is necessary.
Our use of `const vec&` parameters helps to show you where copying needs to
happen.

While `std::vector` uses the heap, if you are using `std::vector` well, you
shouldn't have directly interact with the heap at all.  The reference solution
does not call `new` or `delete`, except in places that the starter code already
calls `new` or `delete`.  A side effect of this fact is that there should be no
reason to worry about memory leaks.

As you read through the details of this assignment, keep in mind that subsequent
assignments will build upon this... so as you craft a solution, be sure to think
about how to make it maintainable.  C++ has many features that make it easy to
extend your code.  The `auto` keyword is one.  In-line initialization of arrays
and structs is another.

**Start Early**.  Just reading the code and understanding what is happening
takes time.  If you start reading the assignment early, you'll give yourself
time to think about what is supposed to be happening, and that will help you to
figure out what you will need to do.

When it comes time to implement functions in the client and server, you will
probably want to proceed in the following order: KEY, REG, SAV, BYE, ALL, SET,
GET.

As always, please be careful about not committing unnecessary files into your
repository.

Your programs should never require keyboard input. In particular, the client
should get all its parameters from the command line.

Your server should **not** store plain-text passwords in the file.

## Grading

If the script passes when using your client with our server, and when using our
client with your server, then unless you have done something that makes your
system vulnerable to TOCTOU attacks (such as saving data to disk before
encrypting it), you will receive full "functionality" points.  We reserve the
right to deduct "style" points if your code is especially convoluted.  Please be
sure to use your tools well.  For example, Visual Studio Code (and emacs, and
vim) have features that auto-format your code.  You should use these features.

If the script does not pass, then the professor and TAs will try to determine
how much partial credit can be assigned.  There are three parts of the
assignment that we will grade.  They are listed below, along with the files
related to each:

* Is the AES cryptography implemented correctly?
  * Files: crypto.cc
* Do the client and server correctly parse the messages they send to each other?
  * Files: client_commands.cc, server_parsing.cc, and server_commands.cc
* Is the directory implemented correctly?
  * Files: server_storage.cc

Note that the script can take flags VERBOSE, SERVER, and CLIENT.  VERBOSE causes
it to print output that will be useful when you try to run the client and
server.  SERVER and CLIENT cause the script to use the reference solution for
the server and client, respectively.  You should use these to be sure that your
implementations are correct.

## Notes About the Reference Solution

In the following subsections, you will find some details about the reference
solution.

### common/crypto.cc

This will probably give more students trouble than any other part of the
assignment, because the OpenSSL documentation is a bit spotty.  The body of
`aes_crypt_message()` is 29 lines of code, plus whitespace and newlines.
Knowing when and how to call `EVP_CipherFinal_ex` is important.  Doing a
`CipherUpdate` on a zero-byte block before calling `CipherFinal` is a bit
easier, in terms of the logic, than not. The code from the tutorial is a good
guide, but since it works on files, it needs some modification.

### server/server_parsing.cc

In the reference solution, the file is 128 lines long.  There is one helper
function:

```c++
/// Helper method to check if the provided block of data is a kblock
///
/// @param block The block of data
///
/// @returns true if it is a kblock, false otherwise
bool is_kblock(vec &block);
```

The `serve_client()` function has about 52 lines of code.  It employs some nice
code-saving techniques, like using an array of functions when dispatching to the
right command:

```c++
  // Iterate through possible commands, pick the right one, run it
  vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(server_cmd_reg) *cmds[] = {server_cmd_reg, server_cmd_bye,
                                      server_cmd_sav, server_cmd_set,
                                      server_cmd_get, server_cmd_all};
  for (size_t i = 0; i < s.size(); ++i) {
    if (cmd == s[i]) {
      return cmds[i](sd, storage, aes_ctx, ablock);
    }
  }
```

### client/client_commands.cc

In the reference solution, the file is about 257 lines long.  It uses this
function to save a small number of lines of repeated code.

```c++
/// Check if the provided result vector is a string representation of ERR_CRYPTO
///
/// @param v The vector being compared to RES_ERR_CRYPTO
///
/// @returns true if the vector contents are RES_ERR_CRYPTO, false otherwise
bool check_err_crypto(const vec &v);
```

In addition, this function is very useful for simplifying `client_get()` and
`client_all()`:

```c++
/// If a buffer consists of OKbbbbd+, where bbbb is a 4-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const vec &buf, const string &filename);
```

Likewise, this function simplifies the production of ablocks:

```c++
/**
 * Create the beginning of an ablock, consisting of the username and password
 *
 * @param user The username
 * @param pass The password
 */
vec auth_msg(const string &user, const string &pass);
```

The most important helper function is this one:

```c++
/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// Many of the messages in our server have a common form (@rblock.@ablock):
///   - @rblock padR(enc(pubkey, "CMD".aeskey.length(@msg)))
///   - @ablock enc(aeskey, @msg)
///
/// @param sd  An open socket
/// @param pub The server's public key, for encrypting the aes key
/// @param cmd The command that is being sent
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (decrypted) result, or an empty vector on error
vec client_send_cmd(int sd, RSA *pub, const string &cmd, const vec &msg);
```

The reference implementation is about 40 lines.  You won't want to write it at
first... figure out how to do REG and SET, and then you'll know what needs to go
in it.  Note that the function will help with REG, BYE, SAV, SET, GET, and ALL.
For example, here's the body of `client_get()` when the helper functions are
done:

```c++
  vec msg = auth_msg(user, pass);
  vec_append(msg, getname.length());
  vec_append(msg, getname);
  auto res = client_send_cmd(sd, pubkey, REQ_GET, msg);
  send_result_to_file(res, getname + ".file.dat");
```

(Yes, just 5 lines... the hard work is in `client_send_cmd` and
`send_result_to_file`).

### server/server_commands.cc

You may want to write a few helper functions here, too, especially for parsing
the lengths and strings in a decrypted input stream.  The reference solution
takes about 245 lines of code to complete this file.  There is a fair bit of
copy-and-paste from one command to the next.

### server/server_storage.cc

In the reference solution, this file is about 300 lines (this count includes the
150 lines that are given in the handout).  `persist()` and `load()` take the most
code by far, because file I/O is tedious in C++.  The other methods should not
be challenging as long as you understand how the `std::unordered_map` works.  If
you are unsure, `http://cppreference.com/` is an excellent resource.  Google
will usually send you directly to the correct page.

One important aspect of this code is that it uses the "private implementation"
(PIMPL) pattern.  PIMPL avoids exposing anything private in the header file.
Using the PIMPL pattern is key to the instructor and TAs being able to give you
partial solutions, so please make sure to understand what it does.

