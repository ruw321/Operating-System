#include <cstdio>
#include <iostream>
#include <openssl/md5.h>
#include <unistd.h>
#include <unordered_map>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/hashtable.h"
#include "../common/mru.h"
#include "../common/protocol.h"
#include "../common/vec.h"
#include "../common/file.h"

#include "server_authtableentry.h"
#include "server_persist.h"
#include "server_quotas.h"
#include "server_storage.h"

using namespace std;

/// Storage::Internal is the private struct that holds all of the fields of the
/// Storage object.  Organizing the fields as an Internal is part of the PIMPL
/// pattern.
struct Storage::Internal {
  /// A unique 8-byte code to use as a prefix each time an AuthTable Entry is
  /// written to disk.
  inline static const string AUTHENTRY = "AUTHAUTH";

  /// A unique 8-byte code to use as a prefix each time a KV pair is written to
  /// disk.
  inline static const string KVENTRY = "KVKVKVKV";

  /// A unique 8-byte code for incremental persistence of changes to the auth
  /// table
  inline static const string AUTHDIFF = "AUTHDIFF";

  /// A unique 8-byte code for incremental persistence of updates to the kv
  /// store
  inline static const string KVUPDATE = "KVUPDATE";

  /// A unique 8-byte code for incremental persistence of deletes to the kv
  /// store
  inline static const string KVDELETE = "KVDELETE";

  /// The map of authentication information, indexed by username
  ConcurrentHashTable<string, AuthTableEntry> auth_table;

  /// The map of key/value pairs
  ConcurrentHashTable<string, vec> kv_store;

  /// filename is the name of the file from which the Storage object was loaded,
  /// and to which we persist the Storage object every time it changes
  string filename = "";

  /// The open file
  FILE *file = nullptr;

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The MRU table for tracking the most recently used keys
  mru_manager mru;

  /// A table for tracking quotas
  ConcurrentHashTable<string, Quotas *> quota_table;

  /// Construct the Storage::Internal object by setting the filename and bucket
  /// count
  ///
  /// @param fname       The name of the file that should be used to load/store
  ///                    the data
  /// @param num_buckets The number of buckets for the hash
  Internal(string fname, size_t num_buckets, size_t upq, size_t dnq, size_t rqq,
           double qd, size_t top)
      : auth_table(num_buckets), kv_store(num_buckets), filename(fname),
        up_quota(upq), down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(top),
        quota_table(num_buckets) {}

  // NB: You may want to add a function here for interacting with the quota
  // table to check a user's quota
};

/// Construct an empty object and specify the file from which it should be
/// loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname       The name of the file that should be used to load/store
///                    the data
/// @param num_buckets The number of buckets for the hash
Storage::Storage(const string &fname, size_t num_buckets, size_t upq,
                 size_t dnq, size_t rqq, double qd, size_t top)
    : fields(new Internal(fname, num_buckets, upq, dnq, rqq, qd, top)) {}

/// Destructor for the storage object.
///
/// NB: The compiler doesn't know that it can create the default destructor in
///     the .h file, because PIMPL prevents it from knowing the size of
///     Storage::Internal.  Now that we have reified Storage::Internal, the
///     compiler can make a destructor for us.
Storage::~Storage() = default;

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
  return string(digest, digest+16);
}

/// Populate the Storage object by loading this.filename.  Note that load()
/// begins by clearing the maps, so that when the call is complete,
/// exactly and only the contents of the file are in the Storage object.
///
/// @returns false if any error is encountered in the file, and true
///          otherwise.  Note that a non-existent file is not an error.
bool Storage::load() {
  // TODO: loading a file should always clear the MRU, if it wasn't already
  // clear
  fields->mru.clear();

  // Open in r+ mode, so that we can append later on...
  fields->file = fopen(fields->filename.c_str(), "r+");
  if (fields->file == nullptr) {
    cerr << "File not found: " << fields->filename << endl;
    // Now we need to re-fopen() it in w mode, which will create a new file.
    fields->file = fopen(fields->filename.c_str(), "w");
    return true;
  }

  //load data and store in auth_table
  //error empty file
  int index = 0;
  vec data = load_entire_file(fields->filename);
  fields->file = fopen(fields->filename.c_str(), "ab");
  if (data.size() == 0) {
    cerr << "Error file is empty\n";
    return false;
  }
  //empty functions for lambdas
  std::function<void()> empty_func = [](){};
  //loop for storing data
  while (index < (int)data.size()) {

    //check authauth or kvkvkvkv
    if (index + 8 > int(data.size())) {
      cerr << "AUTHAUTH or KVKVKVKV or AUTHDIFF or KVUPDATE or KVDELETE can't be found \n";
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
      AuthTableEntry new_user;
      new_user.username = username;
      new_user.pass_hash = pass_hash;
      new_user.content = content_vec;
      fields->auth_table.insert(username, new_user, empty_func); //empty lambda
    } 

    else if(auth_or_kv == "KVKVKVKV") {

      //len(key)
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

      //empty lambda 
      fields->kv_store.insert(key, val, empty_func);
    } 

    // AUTHDIFF: when a user's content changes in the Auth table
    // Magic 8-byte constant AUTHDIFF
    else if (auth_or_kv == "AUTHDIFF") {

      // 4-byte binary write of the length of the username
      if (index + 4 > int(data.size())) {
        cerr << "Length of the username can't be found \n";
        return false;
      }
      int len_user = *(int *)(data.data() + index);
      index += 4;

      // Binary write of the bytes of the username
      if (index + len_user > int(data.size())) {
        cerr << "Username can't be found \n";
        return false;
      }
      string username(data.begin() + index, data.begin() + index + len_user);
      index += len_user;

      // Binary write of num_bytes of the content
      // If num_bytes > 0, a binary write of the bytes field
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

      //redo changing the content
      auto content_change = [&](AuthTableEntry &entry){
        entry.content = content_vec;
      };
      fields->auth_table.do_with(username, content_change);
    }

    // KVUPDATE: when a key's value is changed via upsert
    // Magic 8-byte constant KVUPDATE
    else if(auth_or_kv == "KVUPDATE") {

      // 4-byte binary write of the length of the key
      if (index + 4 > int(data.size())) {
        cerr << "Length of the key can't be found \n";
        return false;
      }
      int len_key = *(int *)(data.data() + index);
      index += 4;

      // Binary write of the bytes of the key
      if (index + len_key > int(data.size())) {
        cerr << "Key can't be found \n";
        return false;
      }
      string key(data.begin() + index, data.begin() + index + len_key);
      index += len_key;

      // Binary write of the length of value
      if (index + 4 > int(data.size())) {
        cerr << "Length of the val can't be found \n";
        return false;
      }
      int len_val = *(int *)(data.data() + index);
      index += 4;

      // Binary write of the bytes of value
      if (index + len_val > int(data.size())) {
        cerr << "Val can't be found \n";
        return false;
      }
      vec val(data.begin() + index, data.begin() + index + len_val);
      index += len_val;

      //redo the operation of changing the key's value
      if (fields->kv_store.upsert(key, val, empty_func, empty_func)) {
        cout << "Insert Successful \n";
      } else {
        cout << "Update Successful \n";
      }
    }

    // KVDELETE: when a key is removed from the key/value store
    // Magic 8-byte constant KVDELETE
    else if (auth_or_kv == "KVDELETE") {
      // 4-byte binary write of the length of the key
      if (index + 4 > int(data.size())) {
        cerr << "Length of the key can't be found \n";
        return false;
      }
      int len_key = *(int *)(data.data() + index);
      index += 4;

      // Binary write of the bytes of the key
      if (index + len_key > int(data.size())) {
        cerr << "Key can't be found \n";
        return false;
      }
      string key(data.begin() + index, data.begin() + index + len_key);
      index += len_key;

      //redo delete
      if (!(fields->kv_store.remove(key, empty_func))) {
        cerr << "Key can't be found \n";
        return false;
      }
    }

    else {
      cerr << "Cannot define authauth or kvkvkvkv or AUTHDIFF or KVUPDATE or KVDELETE\n";
      return false;
    }

  } //end of while loop

  //successfully load data
  cerr << "Loaded: " << fields->filename << endl;
  return true;
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

  AuthTableEntry new_user = {user_name, hashPassword(pass), vec_from_string("")};
  Quotas* new_quota = new Quotas({quota_tracker(fields->up_quota, fields->quota_dur),
                                  quota_tracker(fields->down_quota, fields->quota_dur),
                                  quota_tracker(fields->req_quota, fields->quota_dur)});
  
  //initializing to add to the file
  size_t bytes = 0;
  vec data = vec_from_string("");

  //lamda for adding a user to the file 
  auto append_AUTHAUTH = [&](){
    fields->quota_table.insert(user_name, new_quota, [](){}); 
    vec_append(data, fields->AUTHENTRY);
    vec_append(data, user_name.length());
    vec_append(data, user_name);
    vec_append(data, new_user.pass_hash.length());
    vec_append(data, new_user.pass_hash);
    vec_append(data, new_user.content.size());
    vec_append(data, new_user.content);
    bytes += 20 + user_name.length() + new_user.pass_hash.length() + new_user.content.size();
    fwrite((char*)data.data(), sizeof(char), bytes, fields->file);
    if(ferror(fields->file)){
      cerr << "error on write()\n";
    } 
    //has to flush before sync
    fflush(fields->file);
    fsync(fileno(fields->file)); 
  };

  bool result = fields->auth_table.insert(user_name, new_user, append_AUTHAUTH);
  return result;
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
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //initializing to add to the file
  size_t bytes = 0;
  vec data = vec_from_string("");

  //lamda to set user content
  auto append_AUTHDIFF = [&](){
    vec_append(data, fields->AUTHDIFF);
    vec_append(data, user_name.length());
    vec_append(data, user_name);
    vec_append(data, content.size());
    vec_append(data, content);
    bytes += 16 + user_name.length() + content.size();
    fwrite((char*)data.data(), sizeof(char), bytes, fields->file);
    if(ferror(fields->file)){
      cerr << "error on write()\n";
    } 
    fflush(fields->file);
    fsync(fileno(fields->file)); 
  };

  AuthTableEntry entry;
  entry.username = user_name;
  entry.pass_hash = hashPassword(pass);
  entry.content = content;
  fields->auth_table.upsert(user_name, entry, append_AUTHDIFF, append_AUTHDIFF);
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
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry){})) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //generate lambda to append val of key
  vec ok = vec_from_string(RES_OK);
  int size;
  auto append_content = [&ok, &size](AuthTableEntry entry){
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
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry){})) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass)) {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //generate lambda to append all keys
  vec alluser = vec_from_string("");
  auto append_username = [&alluser](string username, AuthTableEntry entry){
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
  auto get_pass = [&pass_hash](AuthTableEntry entry){
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
  auto append_authauth = [&](string username, AuthTableEntry entry){
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

  //lambda to write and rename 
  auto write_and_rename = [&](){
    if(!write_file(tmp_filename, (char*)data.data(), bytes)){
      cerr << "error on write()\n";
    } 
    if(file_exists(fields->filename)){
      remove(fields->filename.c_str());
    }
    fclose(fields->file);
    rename(tmp_filename.c_str(), fields->filename.c_str()); 
    fields->file = fopen(fields->filename.c_str(), "ab");
  };

  //append auth and kv to the vec_data
  fields->auth_table.do_all_readonly(append_authauth, [&](){
    fields->kv_store.do_all_readonly(append_kvkvkvkv, write_and_rename);
  });
}

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
  
  ///check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_NO_USER);
  }

  ///check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  bool request_not_violate = false;
  bool upload_not_violate = false;

  fields->quota_table.do_with(user_name, [&](Quotas* quota) {
    if (quota->requests.check(1)){
      request_not_violate = true;
      if (quota->uploads.check(val.size())){
        upload_not_violate = true;
        quota->uploads.add(val.size());
      }
    }
    quota->requests.add(1);
  });

  ///check request violation
  if (!request_not_violate) {
    return vec_from_string(RES_ERR_QUOTA_REQ);
  }

  ///check unload violation
  if (!upload_not_violate) {
    return vec_from_string(RES_ERR_QUOTA_UP);
  }

  //initializing to add to the file
  size_t bytes = 0;
  vec data = vec_from_string("");
  //lamda to append adduser
  auto append_KVENTRY = [&](){
    vec_append(data, fields->KVENTRY);
    vec_append(data, key.length());
    vec_append(data, key);
    vec_append(data, val.size());
    vec_append(data, val);
    bytes += 16 + key.length() + val.size();
    fwrite((char*)data.data(), sizeof(char), bytes, fields->file);
    if(ferror(fields->file)){
      cerr << "error on write()\n";
    } 
    fflush(fields->file);
    fsync(fileno(fields->file));
    fields->mru.insert(key);
  };

  //check if key exists
  if(!fields->kv_store.insert(key, val, append_KVENTRY)){
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
  
  ///check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [&](AuthTableEntry entry){})) {
    return {false, vec_from_string(RES_ERR_NO_USER)};
  }

  ///check if the password matches
  if (!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  bool request_not_violate = false;
  bool download_not_violate = false;

  //generate lambda to append val of key
  vec ok = vec_from_string(RES_OK);
  auto append_val = [&](vec val){
    vec_append(ok, val.size());
    vec_append(ok, val);
    fields->quota_table.do_with(user_name, [&](Quotas* quota) {
      if (quota->requests.check(1)){
        request_not_violate = true;
        if (quota->downloads.check(val.size())){
          download_not_violate = true;
          quota->downloads.add(val.size());
          fields->mru.insert(key);
        }
      }
      quota->requests.add(1);
    });
  };

  //if key does not exists, returns error 
  //else, returns ok
  if (!fields->kv_store.do_with_readonly(key, append_val)) {
    return {true, vec_from_string(RES_ERR_KEY)};
  }

  ///check request violation
  if (!request_not_violate) {
    return {true, vec_from_string(RES_ERR_QUOTA_REQ)};
  }

  ///check unload violation
  if (!download_not_violate) {
    return {true, vec_from_string(RES_ERR_QUOTA_DOWN)};
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

  ///check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_NO_USER);
  }

  ///check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  bool request_not_violate = false;

  fields->quota_table.do_with(user_name, [&](Quotas* quota) {
    if (quota->requests.check(1)){
      request_not_violate = true;
    }
    quota->requests.add(1);
  });

  ///check request violation
  if (!request_not_violate) {
    return vec_from_string(RES_ERR_QUOTA_REQ);
  }

  //initializing to add to the file
  size_t bytes = 0;
  vec data = vec_from_string("");
  //lamda to append adduser
  auto append_KVDELETE = [&](){
    vec_append(data, fields->KVDELETE);
    vec_append(data, key.length());
    vec_append(data, key);
    bytes += 12 + key.length();
    fwrite((char*)data.data(), sizeof(char), bytes, fields->file);
    if(ferror(fields->file)){
      cerr << "error on write()\n";
    } 
    fflush(fields->file);
    fsync(fileno(fields->file));
    fields->mru.remove(key);
  };

  //error when key does not exist
  //ok on successfully delete 
  if(!fields->kv_store.remove(key, append_KVDELETE)){
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

  ///check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry){})) {
    return vec_from_string(RES_ERR_NO_USER);
  }

  ///check if the password matches
  if (!auth(user_name, pass)) {
    return vec_from_string(RES_ERR_LOGIN);
  }

  bool request_not_violate = false;
  bool upload_not_violate = false;

  fields->quota_table.do_with(user_name, [&](Quotas* quota) {
    if (quota->requests.check(1)){
      request_not_violate = true;
      if (quota->uploads.check(val.size())){
        upload_not_violate = true;
        quota->uploads.add(val.size());
      }
    }
    quota->requests.add(1);
  });

  ///check request violation
  if (!request_not_violate) {
    return vec_from_string(RES_ERR_QUOTA_REQ);
  }

  ///check unload violation
  if (!upload_not_violate) {
    return vec_from_string(RES_ERR_QUOTA_UP);
  }

  //initializing to add to the file
  size_t bytes = 0;
  vec data = vec_from_string("");
  //lambda to add user
  auto append_KVENTRY = [&](){
    vec_append(data, fields->KVENTRY);
    vec_append(data, key.length());
    vec_append(data, key);
    vec_append(data, val.size());
    vec_append(data, val);
    bytes += 16 + key.length() + val.size();
    fwrite((char*)data.data(), sizeof(char), bytes, fields->file);
    if(ferror(fields->file)){
      cerr << "error on write()\n";
    } 
    fflush(fields->file);
    fsync(fileno(fields->file));
    fields->mru.insert(key);
  };
  //lambda to append adduser
  auto append_KVUPDATE = [&](){
    vec_append(data, fields->KVUPDATE);
    vec_append(data, key.length());
    vec_append(data, key);
    vec_append(data, val.size());
    vec_append(data, val);
    bytes += 16 + key.length() + val.size();
    fwrite((char*)data.data(), sizeof(char), bytes, fields->file);
    if(ferror(fields->file)){
      cerr << "error on write()\n";
    } 
    fflush(fields->file);
    fsync(fileno(fields->file));
    fields->mru.insert(key);
  };

  //if key exists, return ok-upsert
  //else, return ok-insert
  if(!fields->kv_store.upsert(key, val, append_KVENTRY, append_KVUPDATE)){
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

  ///check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry){})) {
    return {false, vec_from_string(RES_ERR_NO_USER)};
  }

  ///check if the password matches
  if (!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  bool request_not_violate = false;
  bool download_not_violate = false;

  //generate lambda to append all keys
  vec alluser = vec_from_string("");
  auto append_username = [&](string key, vec val){
    vec_append(alluser, key);
    vec_append(alluser, "\r");
  };

  auto check_quota = [&](){
    fields->quota_table.do_with(user_name, [&](Quotas* quota) {
      if (quota->requests.check(1)){
        request_not_violate = true;
        if (quota->downloads.check(alluser.size())){
          download_not_violate = true;
          quota->downloads.add(alluser.size());
        }
      }
      quota->requests.add(1);
    });
  };

  //use helper function to avoid data racing
  fields->kv_store.do_all_readonly(append_username, check_quota);

  ///check request violation
  if (!request_not_violate) {
    return {true, vec_from_string(RES_ERR_QUOTA_REQ)};
  }

  ///check unload violation
  if (!download_not_violate) {
    return {true, vec_from_string(RES_ERR_QUOTA_DOWN)};
  }

  vec ok = vec_from_string(RES_OK);
  vec_append(ok, alluser.size());
  vec_append(ok, alluser);
  return {true, ok};
};

/// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
/// string
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
///
/// @returns A pair with a bool to indicate errors, and a vec with the result
///          (possibly an error message).
pair<bool, vec> Storage::kv_top(const string &user_name, const string &pass) {

  ///check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [&](AuthTableEntry entry){})) {
    return {false, vec_from_string(RES_ERR_NO_USER)};
  }

  ///check if the password matches
  if (!auth(user_name, pass)) {
    return {false, vec_from_string(RES_ERR_LOGIN)};
  }

  bool request_not_violate = false;
  bool download_not_violate = false;

  //generate lambda to append val of key
  vec ok = vec_from_string(RES_OK);
    
  fields->quota_table.do_with(user_name, [&](Quotas* quota) {
    if (quota->requests.check(1)){
      request_not_violate = true;
      string str = fields->mru.get();
      if (quota->downloads.check(str.length())){
        download_not_violate = true;
        quota->downloads.add(str.length());
        vec_append(ok, str.length());
        vec_append(ok, str);
      }
    }
    quota->requests.add(1);
  });

  ///check request violation
  if (!request_not_violate) {
    return {true, vec_from_string(RES_ERR_QUOTA_REQ)};
  }

  ///check unload violation
  if (!download_not_violate) {
    return {true, vec_from_string(RES_ERR_QUOTA_DOWN)};
  }

  return {true, ok};
};

/// Close any open files related to incremental persistence
///
/// NB: this cannot be called until all threads have stopped accessing the
///     Storage object
void Storage::shutdown() {
  fclose(fields->file);
}
