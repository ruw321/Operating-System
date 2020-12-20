#include <atomic>
#include <dlfcn.h>
#include <iostream>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/file.h"
#include "../common/functypes.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "func_table.h"

using namespace std;

/// func_table::Internal is the private struct that holds all of the fields of
/// the func_table object.  Organizing the fields as an Internal is part of the
/// PIMPL pattern.
///
/// Among other things, this struct will probably need to have a map of loaded
/// functions and a shared_mutex.  The map will probably need to hold some kind
/// of struct that is able to support graceful shutdown, as well as the
/// association of names to map/reduce functions
struct func_table::Internal
{
  //shared mutex
  mutable shared_mutex mutex_;

  //to open .so files
  vector<void *> open_handles;

  //map of loaded functions
  map<string, pair<map_func, reduce_func>> funcMap;

  //used for making unique names for the files 
  atomic_int x;
};

/// Construct a function table for storing registered functions
func_table::func_table() : fields(new Internal()) {}

/// Destruct a function table
func_table::~func_table() = default;

/// Register the map() and reduce() functions from the provided .so, and
/// associate them with the provided name.
///
/// @param mrname The name to associate with the functions
/// @param so     The so contents from which to find the functions
///
/// @returns a vec with a status message
vec func_table::register_mr(const string &mrname, const vec &so)
{
  //using counter to generate a unique name everytime
  string filename = "./file" + to_string(fields->x++) + ".so"; 
  if (!write_file(filename, (const char *)so.data(), so.size()))
  {
    return vec_from_string(RES_ERR_SO);
  }

  //load the dynamic library file
  void *handle = dlopen(filename.c_str(), RTLD_LAZY);
  if (!handle)
  {
    return vec_from_string(RES_ERR_SO);
  }
  
  //get the map and reduce function from so 
  auto f = (map_func)dlsym(handle, "map");
  if (dlerror() != NULL){
    //close the dynamic library and return error
    dlclose(handle);
    return vec_from_string(RES_ERR_SO);
  }
  auto f2 = (reduce_func)dlsym(handle, "reduce");
  if (dlerror() != NULL){
    //close the dynamic library and return error
    dlclose(handle);
    return vec_from_string(RES_ERR_SO);
  }

  //unique lock since it is a write operation
  std::unique_lock lock(fields->mutex_);
  fields->open_handles.push_back(handle);
  auto result = fields->funcMap.emplace(mrname, make_pair(f, f2));
  cout << result.second << endl;
  if (result.second == false)
  {
    return vec_from_string(RES_ERR_FUNC);
  }
  return vec_from_string(RES_OK);
}

/// Get the (already-registered) map() and reduce() functions asssociated with
/// a name.
///
/// @param name The name with which the functions were mapped
///
/// @returns A pair of function pointers, or {nullptr, nullptr} on error
pair<map_func, reduce_func> func_table::get_mr(const string &mrname)
{
  //shared lock since it is a read operation
  std::shared_lock lock(fields->mutex_);
  auto functions = fields->funcMap.find(mrname);
  if (functions == fields->funcMap.end())
  {
    return {nullptr, nullptr};
  }
  return functions->second;
}

/// When the function table shuts down, we need to de-register all the .so
/// files that were loaded.
void func_table::shutdown() {
  for (auto i : fields->open_handles) {
    dlclose(i);
  }
  //remove the so files after shutdown
  int result = system("rm file*.so");
  if (result < 0) {
    cerr << "error deleting so files" << endl;
  }
}