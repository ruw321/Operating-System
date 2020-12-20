#include <sys/wait.h>
#include <unistd.h>

#include "../common/contextmanager.h"
#include "../common/protocol.h"

#include "server_storage.h"
#include "server_storage_internal.h"

using namespace std;

/// Perform the child half of a map/reduce communication
///
/// @param in_fd   The fd from which to read data from the parent
/// @param out_fd  The fd on which to write data to the parent
/// @param mapper  The map function to run on each pair received from the
///                parent
/// @param reducer The reduce function to run on the results of mapper
///
/// @returns false if any error occurred, true otherwise
bool child_mr(int in_fd, int out_fd, map_func mapper, reduce_func reducer)
{
  //input for reduce func
  vector<vec> reduced;

  //keep reading until the size of the key is 0
  while (true)
  {
    //reading the key length and then the key
    int key_len;
    int readSize = read(in_fd, &key_len, 4);
    if (readSize == 0)
    { //end of the file
      printf("%d", readSize);
      break;
    }
    char key[key_len];
    readSize = read(in_fd, key, key_len);

    //reading the value length and then the value
    int value_len;
    readSize = read(in_fd, &value_len, 4);
    char value[value_len];
    readSize = read(in_fd, value, value_len);

    //convert key to string and value to vec
    string string_key(key, key_len);
    string string_value(value, value_len);
    vec vec_value = vec_from_string(string_value);

    //apply map function all the key and value
    vec mapresult = mapper(string_key, vec_value);

    //sum all the result from map func for reduce func later
    reduced.push_back(mapresult);
  }
  //close the reading end since I am done reading
  close(in_fd);

  //apply reduce func
  vec finalResult = reducer(reduced);

  //write the return value from reduce_func to the pipe
  int writeSize = write(out_fd, finalResult.data(), finalResult.size());

  if (writeSize != int(finalResult.size()))
  {
    return false;
  }

  //done writing so close the write end
  close(out_fd);
  return true;
}

/// Register a .so with the function table
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, used to authenticate
/// @param mrname    The name to use for the registration
/// @param so        The .so file contents to register
///
/// @returns A vec with the result message
vec Storage::register_mr(const string &user_name, const string &pass,
                         const string &mrname, const vec &so)
{
  //check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry) {}))
  {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if the password matches
  if (!auth(user_name, pass))
  {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //check if user is the admin
  if (fields->admin_name != user_name)
  {
    return vec_from_string(RES_ERR_LOGIN);
  }

  //if the credentials work, the register the function
  return fields->funcs.register_mr(mrname, so);
};

/// Run a map/reduce on all the key/value pairs of the kv_store
///
/// @param user_name The name of the user who made the request
/// @param pass      The password for the user, to authenticate
/// @param mrname    The name of the map/reduce functions to use
///
/// @returns A pair with a bool to indicate error, and a vector indicating the
///          message (possibly an error message) that is the result of the
///          attempt
pair<bool, vec> Storage::invoke_mr(const string &user_name, const string &pass,
                                   const string &mrname)
{
  //check if user exists
  if (!fields->auth_table.do_with_readonly(user_name, [](AuthTableEntry entry) {}))
  {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  //check if the password matches
  if (!auth(user_name, pass))
  {
    return {true, vec_from_string(RES_ERR_LOGIN)};
  }

  // //check if user is the admin
  // if (fields->admin_name != user_name)
  // {
  //   return {true, vec_from_string(RES_ERR_SO)};
  // }

  int fd1[2]; // First pipe to send from parent
  int fd2[2]; // Second pipe to send from child

  if (pipe(fd1) == -1)
  {
    return {true, vec_from_string(RES_ERR_SERVER)};
  }
  if (pipe(fd2) == -1)
  {
    return {true, vec_from_string(RES_ERR_SERVER)};
  }

  //vector to store values in
  vec result;
  pid_t pid = fork();

  if (pid < 0)
  {
    return {true, vec_from_string(RES_ERR_SERVER)};
  }
  //parent process
  else if (pid > 0)
  {
    // Close reading end of parent pipe amd write end of child pipe
    close(fd1[0]);
    close(fd2[1]);

    //store all the key and value in a vector
    fields->kv_store.do_all_readonly([&](string key, vec value) -> void {
      vec_append(result, key.size());
      vec_append(result, key);
      vec_append(result, value.size());
      vec_append(result, value); }, [&]() {});

    //put the vector on the pipe
    size_t writeSize = write(fd1[1], (const char *)result.data(), result.size());

    if (writeSize == 0)
    {
      return {true, vec_from_string(RES_ERR_SERVER)};
    }
    //close parent pipe writing end after done writing
    close(fd1[1]);

    int status;
    // Wait for child to send result
    pid_t wait = waitpid(pid, &status, WUNTRACED | WCONTINUED);
    if (wait == -1)
    {
      return {true, vec_from_string(RES_ERR_SERVER)};
    }
    if (WIFEXITED(status))
    {
      int exitStatus = WEXITSTATUS(status);
      //failed to exit
      if (exitStatus != 0)
      {
        return {true, vec_from_string(RES_ERR_SERVER)};
      }
    }

    //after waiting, read the child pipe
    char bitBuffer;
    //vector to store the vec from reduce function
    vec child_vec;
    while (read(fd2[0], &bitBuffer, 1))
    {
      child_vec.push_back(bitBuffer);
    }

    //close child pipe reading end after done reading
    close(fd2[0]);

    return {false, child_vec};
  }
  else { //child process

    //close the parent pipe write end and child pipe read end
    close(fd1[1]);
    close(fd2[0]);
    
    //get functipons from get mr
    auto functions = fields->funcs.get_mr(mrname);
    
    if (child_mr(fd1[0], fd2[1], functions.first, functions.second))
    {
      exit(EXIT_SUCCESS);
    }
    else
    {
      exit(EXIT_FAILURE);
    }
  }

  return {true, vec_from_string(RES_ERR_SO)};

}







