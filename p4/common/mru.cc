#include <deque>
#include <mutex>

#include "mru.h"

using namespace std;

/// mru_manager::Internal is the class that stores all the members of a
/// mru_manager object. To avoid pulling too much into the .h file, we are using
/// the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct mru_manager::Internal {

  /// The deque containing values
  std::deque<string> values;
  /// The maximum number of elements
  size_t max_size;
  /// Dwayne Johnson
  std::mutex lock;

  /// Construct the Internal object by setting the fields that are
  /// user-specified
  ///
  /// @param elements The number of elements that can be tracked
  Internal(size_t elements) {
    this->max_size = elements;
  }
};

/// Construct the mru_manager by specifying how many things it should track
mru_manager::mru_manager(size_t elements) : fields(new Internal(elements)) {}

/// Destruct an mru_manager
mru_manager::~mru_manager() = default;

/// Insert an element into the mru_manager, making sure that (a) there are no
/// duplicates, and (b) the manager holds no more than /max_size/ elements.
///
/// @param elt The element to insert
void mru_manager::insert(const string &elt) {
  lock_guard<mutex> lock(fields->lock);
  /// remove the duplicate value
  for(size_t i = 0; i < fields->values.size(); i++){
    if(elt.compare(fields->values[i]) == 0){
      fields->values.erase(fields->values.begin() + i);
      break;
    }
  }
  /// pop back if deque reaches the maximum size
  if(fields->max_size == fields->values.size()){
    fields->values.pop_back();
  }
  /// push front the new value
  fields->values.push_front(elt);
}

/// Remove an instance of an element from the mru_manager.  This can leave the
/// manager in a state where it has fewer than max_size elements in it.
///
/// @param elt The element to remove
void mru_manager::remove(const string &elt) {
  lock_guard<mutex> lock(fields->lock);
  /// remove the duplicate value
  for(size_t i = 0; i < fields->values.size(); i++){
    if(elt.compare(fields->values[i]) == 0){
      fields->values.erase(fields->values.begin() + i);
      break;
    }
  }
}

/// Clear the mru_manager
void mru_manager::clear() {
  lock_guard<mutex> lock(fields->lock);
  fields->values.clear();
}

/// Produce a concatenation of the top entries, in order of popularity
///
/// @returns A newline-separated list of values
string mru_manager::get() { 
  lock_guard<mutex> lock(fields->lock);
  string str = "";
  for(size_t i = 0; i < fields->values.size(); i++) {
    str += fields->values[i];
    str += "\n";
  }
  return str;
}