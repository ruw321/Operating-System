#include <iostream>
#include <openssl/md5.h>
#include <unordered_map>
#include <utility>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/hashtable.h"
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
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// A unique 8-byte code to use as a prefix each time a KV pair is written to
  /// disk.
  inline static const string KVENTRY = "KVKVKVKV";

  /// The map of authentication information, indexed by username
  ConcurrentHashTable<string, AuthTableEntry> auth_table;

  /// The map of key/value pairs
  ConcurrentHashTable<string, vec> kv_store;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// Construct the Storage::Internal object by setting the filename and bucket
  /// count
  ///
  /// @param fname       The name of the file that should be used to load/store
  ///                    the data
  /// @param num_buckets The number of buckets for the hash
  Internal(string fname, size_t num_buckets)
      : auth_table(num_buckets), kv_store(num_buckets), filename(fname) {}
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname       The name of the file that should be used to load/store
///                    the data
/// @param num_buckets The number of buckets for the hash
Storage::Storage(const string &fname, size_t num_buckets)
    : fields(new Internal(fname, num_buckets)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

/// Populate the Storage object by loading this.filename.  Note that load()
/// begins by clearing the maps, so that when the call is complete,
/// exactly and only the contents of the file are in the Storage object.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load() {

  fields->auth_table.clear();
  fields->kv_store.clear();

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

    //check authauth or kvkvkvkv
    if (index + 8 > int(data.size())) {
      cerr << "AUTHAUTH or KVKVKVKV can't be found \n";
      return false;
    }
    string auth_or_kv(data.begin() + index, data.begin() + index + 8);
    index += 8;

    if(auth_or_kv == "AUTHAUTH"){

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
      fields->auth_table.insert(username, new_user);
    } 

    else if(auth_or_kv == "KVKVKVKV"){

      //len(user)
      if (index + 4 > int(data.size())) {
        cerr << "Length of the key can't be found \n";
        return false;
      }
      int len_key = *(int *)(data.data() + index);
      index += 4;

      //key
      if (index + len_key > int(data.size())) {
        cerr << "Key can't be found \n";
        return false;
      }
      string key(data.begin() + index, data.begin() + index + len_key);
      index += len_key;

      //len(val)
      if (index + 4 > int(data.size())) {
        cerr << "Length of the val can't be found \n";
        return false;
      }
      int len_val = *(int *)(data.data() + index);
      index += 4;

      //val
      if (index + len_val > int(data.size())) {
        cerr << "Val can't be found \n";
        return false;
      }
      vec val(data.begin() + index, data.begin() + index + len_val);
      index += len_val;

      fields->kv_store.insert(key, val);
    } 

    else {
      cerr << "Cannot define authauth or kvkvkvkv\n";
      return false;
    }

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

  Internal::AuthTableEntry new_user;
  new_user.username = user_name;
  new_user.pass_hash = hashPassword(pass);
  new_user.content = vec_from_string("");
  return fields->auth_table.insert(user_name, new_user);
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
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  Internal::AuthTableEntry entry;
  entry.username = user_name;
  entry.pass_hash = hashPassword(pass);
  entry.content = content;
  fields->auth_table.upsert(user_name, entry);
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
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //generate lambda to append val of key
  vec ok = vec_from_string(RES_OK);
  int size;
  auto append_content = [&ok, &size](Storage::Internal::AuthTableEntry entry){
    size = entry.content.size();
    vec_append(ok, entry.content.size());
    vec_append(ok, entry.content);
  };

  //if key does not exists, returns error 
  //else, returns ok
  if (!fields->auth_table.do_with_readonly(who, append_content)) {
    return {true, vec_from_string(RES_ERR_NO_USER)};
  }
  if (size == 0){
    return {true, vec_from_string(RES_ERR_NO_DATA)};
  }
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
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //generate lambda to append all keys
  vec alluser = vec_from_string("");
  auto append_username = [&alluser](string username,Storage::Internal::AuthTableEntry entry){
    vec_append(alluser, username);
    vec_append(alluser, "\r");
  };

  //use helper function to avoid data racing
  fields->auth_table.do_all_readonly(append_username, [](){});
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

  string pass_hash; 
  auto get_pass = [&pass_hash](Storage::Internal::AuthTableEntry entry){
    pass_hash = entry.pass_hash;
  };
  fields->auth_table.do_with_readonly(user_name, get_pass);
  return hashPassword(pass) == pass_hash;
}

/// Write the entire Storage object to the file specified by this.filename.
/// To ensure durability, Storage must be persisted in two steps.  First, it
/// must be written to a temporary file (this.filename.tmp).  Then the
/// temporary file can be renamed to replace the older version of the Storage
/// object.
void Storage::persist() {

  size_t bytes = 0;
  string tmp_filename = fields->filename + ".tmp";
  vec data = vec_from_string("");

  //lambda to append authauth
  auto append_authauth = [&](string username, Storage::Internal::AuthTableEntry entry){
    vec_append(data, fields->AUTHENTRY);
    vec_append(data, entry.username.length());
    vec_append(data, entry.username);
    vec_append(data, entry.pass_hash.length());
    vec_append(data, entry.pass_hash);
    vec_append(data, entry.content.size());
    if(entry.content.size() != 0){
      vec_append(data, entry.content);
    }
    bytes += 20 + entry.username.length() + entry.pass_hash.length() + entry.content.size();
  };

  //lambda to append kvkvkvkv
  auto append_kvkvkvkv = [&](string key, vec val){
    vec_append(data, fields->KVENTRY);
    vec_append(data, key.length());
    vec_append(data, key);
    vec_append(data, val.size());
    vec_append(data, val);
    bytes += 16 + key.length() + val.size();
  };

  //append auth and kv to the vec_data
  fields->auth_table.do_all_readonly(append_authauth, [](){});
  fields->kv_store.do_all_readonly(append_kvkvkvkv, [](){});
  
  if(!write_file(tmp_filename, (char*)data.data(), bytes)){
    cerr << "error on write()\n";
  } 
  rename(tmp_filename.c_str(), fields->filename.c_str());  
}

/// Shut down the storage when the server stops.
///
/// NB: this is only called when all threads have stopped accessing the
///     Storage object.  As a result, there's nothing left to do, so it's a
///     no-op.
void Storage::shutdown() {}

/// Create a new key/value mapping in the table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose mapping is being created
/// @param val       The value to copy into the map
///
/// @returns A vec with the result message
vec Storage::kv_insert(const string &user_name, const string &pass,
                       const string &key, const vec &val) {

  //check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if key exists
  if(!fields->kv_store.insert(key, val)){
    return vec_from_string(RES_ERR_KEY);
  }
  return vec_from_string(RES_OK);
};

/// Get a copy of the value to which a key is mapped
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose value is being fetched
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          data (possibly an error message) that is the result of the
///          attempt.
pair<bool, vec> Storage::kv_get(const string &user_name, const string &pass,
                                const string &key) {

  //check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  //generate lambda to append val of key
  vec ok = vec_from_string(RES_OK);
  auto append_val = [&ok](vec val){
    vec_append(ok, val.size());
    vec_append(ok, val);
  };

  //if key does not exists, returns error 
  //else, returns ok
  if (!fields->kv_store.do_with_readonly(key, append_val)) {
    return {true, vec_from_string(RES_ERR_KEY)};
  }
  return {true, ok};
};

/// Delete a key/value mapping
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose value is being deleted
///
/// @returns A vec with the result message
vec Storage::kv_delete(const string &user_name, const string &pass,
                       const string &key) {

  //check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //error when key does not exist
  //ok on successfully delete 
  if(!fields->kv_store.remove(key)){
    return vec_from_string(RES_ERR_KEY);
  }
  return vec_from_string(RES_OK);
};

/// Insert or update, so that the given key is mapped to the give value
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param key       The key whose mapping is being upserted
/// @param val       The value to copy into the map
///
/// @returns A vec with the result message.  Note that there are two "OK"
///          messages, depending on whether we get an insert or an update.
vec Storage::kv_upsert(const string &user_name, const string &pass,
                       const string &key, const vec &val) {
  
  //check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //if key exists, return ok-upsert
  //else, return ok-insert
  if(!fields->kv_store.upsert(key, val)){
    return vec_from_string(RES_OKUPD);
  }
  return vec_from_string(RES_OKINS);
};

/// Return all of the keys in the kv_store, as a "\n"-delimited string
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A pair with a bool to indicate errors, and a vec with the result
///          (possibly an error message).
pair<bool, vec> Storage::kv_all(const string &user_name, const string &pass) {

  //check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](Storage::Internal::AuthTableEntry entry){})) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  //generate lambda to append all keys
  vec alluser = vec_from_string("");
  auto append_username = [&alluser](string key, vec val){
    vec_append(alluser, key);
    vec_append(alluser, "\r");
  };

  //use helper function to avoid data racing
  fields->kv_store.do_all_readonly(append_username, [](){});
  vec ok = vec_from_string(RES_OK);
  vec_append(ok, alluser.size());
  vec_append(ok, alluser);
  return {true, ok};

};
