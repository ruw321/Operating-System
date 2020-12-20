#include <iostream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"
#include "server_storage.h"

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal {
  /// AuthTableEntry represents one user stored in the authentication table
  struct AuthTableEntry {
    /// The name of the user; max 64 characters
    string username;

    /// The hashed password.  Note that the password is a max of 128 chars
    string pass_hash;

    /// The user's content
    vec content;
  };

  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  ///
  /// NB: this isn't needed in assignment 1, but will be useful for backwards
  ///     compatibility later on.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// The map of authentication information, indexed by username
  unordered_map<string, AuthTableEntry> auth_table;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// Construct the Storage::Internal object by setting the filename
  ///
  /// @param fname The name of the file that should be used to load/store the
  ///              data
  Internal(const string &fname) : filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname The name of the file that should be used to load/store the
///              data
Storage::Storage(const string &fname) : fields(new Internal(fname)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading an auth_table from this.filename.
/// Note that load() begins by clearing the auth_table, so that when the call
/// is complete, exactly and only the contents of the file are in the
/// auth_table.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load() {

  //clear auth_table to load new data
  fields->auth_table.clear();

  //error file not found
  if (!file_exists(fields->filename)) {
    cerr << "File not found: " << fields->filename << "\n";
    return true;
  }

  //load data and store in auth_table
  //error empty file
  int index = 0;
  vec data = load_entire_file(fields->filename);
  if (data.size() == 0) {
    cerr << "Error file is empty\n";
    return false;
  }

  //loop for storing data
  while (index < (int)data.size()) {
    int auth_len = Storage::Internal::AUTHENTRY.length();
    if (index + auth_len > int(data.size())) {
      cerr << "AUTHAUTH can't be found \n";
      return false;
    }

    //AUTHAUTH
    if (string(data.begin() + index, data.begin() + index + auth_len) != Storage::Internal::AUTHENTRY) {
      cerr << "AUTHAUTH should be here but it's not \n";
      return false;
    }
    index += auth_len;

    //len(user)
    if (index + 4 > int(data.size())) {
      cerr << "Length of the username can't be found \n";
      return false;
    }
    int len_user = *(int *)(data.data() + index);
    index += 4;

    //username
    if (index + len_user > int(data.size())) {
      cerr << "Username can't be found \n";
      return false;
    }
    string username(data.begin() + index, data.begin() + index + len_user);
    index += len_user;

    //len(pass_hash)
    if (index + 4 > int(data.size())) {
      cerr << "Length of pass_hash can't be found \n";
      return false;
    }
    int len_pass_hash = *(int *)(data.data() + index);
    index += 4;

    //pass_hash
    if (index + len_pass_hash > int(data.size())) {
      cerr << "Pass_hash can't be found \n";
      return false;
    }
    string pass_hash(data.begin() + index, data.begin() + index + len_pass_hash);
    index += len_pass_hash;

    //len(content)
    if (index + 4 > int(data.size())) {
      cerr << "Length of content can't be found \n";
      return false;
    }
    int len_content = *(int *)(data.data() + index);
    index += 4;

    //content
    if (index + len_content > int(data.size())) {
      cerr << "Content can't be found \n";
      return false;
    }
    vec content_vec = vec_from_string("");
    if(len_content != 0){
      vec_append(content_vec, vec(data.begin() + index, data.begin() + index + len_content));
    }
    index += len_content;

    //adding user and user's content to auth_table
    Internal::AuthTableEntry new_user;
    new_user.username = username;
    new_user.pass_hash = pass_hash;
    new_user.content = content_vec;
    fields->auth_table[username] = new_user;

  } //end of while loop

  //successfully load data
  cerr << "Loaded: " << fields->filename << endl;
  return true;
}

/// Hash password MD5
/// @param pass The password to hash
///
/// @return Hash string of password
string hashPassword(string pass) {
  unsigned char digest[16];
  MD5_CTX ctx;
  MD5_Init(&ctx);
  MD5_Update(&ctx, (void *)pass.c_str(), pass.length());
  MD5_Final(digest, &ctx);
  return string(digest, digest + 16);
}

/// Create a new entry in the Auth table.  If the user_name already exists, we
/// should return an error.  Otherwise, hash the password, and then save an
/// entry with the username, hashed password, and a zero-byte content.
///
/// @param user_name The user name to register
/// @param pass      The password to associate with that user name
///
/// @returns False if the username already exists, true otherwise
bool Storage::add_user(const string &user_name, const string &pass) {

  //check if user exists
  if (fields->auth_table.find(user_name) != fields->auth_table.end()) {
    return false;
  }
  Internal::AuthTableEntry new_user;
  new_user.username = user_name;
  new_user.pass_hash = hashPassword(pass);
  new_user.content = vec_from_string("");
  fields->auth_table[user_name] = new_user;
  return true;
}

/// Set the data bytes for a user, but do so if and only if the password
/// matches
///
/// @param user_name The name of the user whose content is being set
/// @param pass      The password for the user, used to authenticate
/// @param content   The data to set for this user
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
vec Storage::set_user_data(const string &user_name, const string &pass,
                           const vec &content) {

  //check if user exists
  if (fields->auth_table.find(user_name) == fields->auth_table.end()) {
    cerr << "This user doesn't exist \n";
    return vec_from_string(RES_ERR_NO_USER);
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    cerr << "Wrong password \n";
    return vec_from_string(RES_ERR_LOGIN);
  }

  //every condition passes, set the content
  fields->auth_table[user_name].content = content;
  return vec_from_string(RES_OK);
}

/// Return a copy of the user data for a user, but do so only if the password
/// matches
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param who       The name of the user whose content is being fetched
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          data (possibly an error message) that is the result of the
///          attempt.  Note that "no data" is an error
pair<bool, vec> Storage::get_user_data(const string &user_name,
                                       const string &pass, const string &who) {

  //check if user exists
  if (fields->auth_table.find(user_name) == fields->auth_table.end()) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }
  
  //check if who exists
  if (fields->auth_table.find(who) == fields->auth_table.end()) {
    return {false, vec_from_string(RES_ERR_NO_USER)};
  }
  
  //check data is not empty
  vec content = vec_from_string("");
  content = fields->auth_table[who].content;
  if(content.size() == 0){
    return {false, vec_from_string(RES_ERR_NO_DATA)};
  }
  vec ok = vec_from_string(RES_OK);
  vec_append(ok, content.size());
  vec_append(ok, content);
  return {true, ok};
}

/// Return a newline-delimited string containing all of the usernames in the
/// auth table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A vector with the data, or a vector with an error message
pair<bool, vec> Storage::get_all_users(const string &user_name,
                                       const string &pass) {

  //check if user exists
  if (fields->auth_table.find(user_name) == fields->auth_table.end()) {
    return {false, vec_from_string(RES_ERR_NO_USER)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  vec alluser = vec_from_string("");
  for (auto it = fields->auth_table.begin(); it != fields->auth_table.end(); ++it) {
    vec_append(alluser, it->first);
    vec_append(alluser, "\r");
  }
  vec ok = vec_from_string(RES_OK);
  vec_append(ok, alluser.size());
  vec_append(ok, alluser);
  return {true, ok};
}

/// Authenticate a user
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns True if the user and password are valid, false otherwise
bool Storage::auth(const string &user_name, const string &pass) {
  return hashPassword(pass) == fields->auth_table[user_name].pass_hash;
}

/// Write the entire Storage object (right now just the Auth table) to the
/// file specified by this.filename.  To ensure durability, Storage must be
/// persisted in two steps.  First, it must be written to a temporary file
/// (this.filename.tmp).  Then the temporary file can be renamed to replace
/// the older version of the Storage object.
void Storage::persist() { 

  size_t bytes = 0;
  vec data = vec_from_string("");
  for (auto const &pair : fields->auth_table) {
    vec_append(data, fields->AUTHENTRY);
    vec_append(data, pair.second.username.length());
    vec_append(data, pair.second.username);
    vec_append(data, pair.second.pass_hash.length());
    vec_append(data, pair.second.pass_hash);
    vec_append(data, pair.second.content.size());
    //append content when it exists
    if(pair.second.content.size() != 0){
      vec_append(data, pair.second.content);
    }
    // 8 a_bytes + 4 u_bytes + 4 p_bytes + 4 c_bytes = 20
    // counting nums_of_bytes to write
    bytes += 20 + pair.second.username.length() + pair.second.pass_hash.length() + pair.second.content.size();
  }
  if(!write_file(fields->filename, (char*)data.data(), bytes)){
    cerr << "error on write()\n";
  }  
}

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}
