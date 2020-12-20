#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

/// ConcurrentHashTable is a concurrent hash table (a Key/Value store).  It is
/// not resizable, which means that the O(1) guarantees of a hash table are lost
/// if the number of elements in the table gets too big.
///
/// The ConcurrentHashTable is templated on the Key and Value types
///
/// The general structure of the ConcurrentHashTable is that we have an array of
/// buckets.  Each bucket has a mutex and a vector of entries.  Each entry is a
/// pair, consisting of a key and a value.  We can use std::hash() to choose a
/// bucket from a key.
template <typename K, typename V> class ConcurrentHashTable {

public:

  //each bucket has a lock and an array of pairs K, V
  struct bucket {
    std::mutex lock;
    std::vector<std::pair<K, V>> entry;
  };
  std::vector<bucket*> b_vector;
  size_t num_buckets;
  /// Construct a concurrent hash table by specifying the number of buckets it
  /// should have
  ///
  /// @param _buckets The number of buckets in the concurrent hash table
  ConcurrentHashTable(size_t _buckets) {
    this->num_buckets = _buckets;
    //std::vector<std::mutex> l_array(_buckets);
    for (int i=0; i< int(_buckets); i++) {
      bucket* buc = new bucket();
      this->b_vector.push_back(buc);
    }
  }

  /// Clear the Concurrent Hash Table.  This operation needs to use 2pl
  void clear() {
    //first acquire all the locks 
    for (int i=0; i<int(b_vector.size()); i++) {
      b_vector[i]->lock.lock();
      b_vector[i]->entry.clear();
    }
    //after all the operations, unlock all of them
    for (int i=0; i<int(b_vector.size()); i++) {
      b_vector[i]->lock.unlock();
    }
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table
  bool insert(K key, V val, std::function<void()> on_success) { 
    //generating index from hashing
    int index = std::hash<K>{}(key)%num_buckets;
    //lock guard will release the lock once it goes out of scope
    std::lock_guard<std::mutex> guard(b_vector[index]->lock);
    for (int i = 0 ; i < int(b_vector[index]->entry.size()) ; i++) {
      if (b_vector[index]->entry[i].first == key) {
        return false;
      }
    }
    //insert new element
    b_vector[index]->entry.push_back(std::make_pair(key, val));
    //Code to run if the insertion succeeds
    on_success();
    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @returns true if the key/value was inserted, false if the key already
  ///          existed in the table and was thus updated instead
  bool upsert(K key, V val, std::function<void()> on_ins,
              std::function<void()> on_upd) {
    //generating index from hashing
    int index = std::hash<K>{}(key)%num_buckets;
    //lock guard will release the lock once it goes out of scope
    std::lock_guard<std::mutex> guard(b_vector[index]->lock);
    for (int i = 0 ; i < int(b_vector[index]->entry.size()) ; i++) {
      if (b_vector[index]->entry[i].first == key) {
        b_vector[index]->entry[i].second = val;
        //Code to run if the upsert succeeds as an update
        on_upd();
        return false;
      }
    }
    //insert new element
    b_vector[index]->entry.push_back(std::make_pair(key, val));
    //Code to run if the upsert succeeds as an insert
    on_ins();
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with(K key, std::function<void(V &)> f) { 
    //generating index from hashing
    int index = std::hash<K>{}(key)%num_buckets;
    //lock guard will release the lock once it goes out of scope
    std::lock_guard<std::mutex> guard(b_vector[index]->lock);
    for (int i = 0 ; i < int(b_vector[index]->entry.size()) ; i++) {
      if (b_vector[index]->entry[i].first == key) {
        f(b_vector[index]->entry[i].second);
        return true;
      }
    }
    return false;   
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @returns true if the key existed and the function was applied, false
  ///          otherwise
  bool do_with_readonly(K key, std::function<void(const V &)> f) {
    //same as do_with since V is alreayd declared as const
    //generating index from hashing
    int index = std::hash<K>{}(key)%num_buckets;
    //lock guard will release the lock once it goes out of scope
    std::lock_guard<std::mutex> guard(b_vector[index]->lock);
    for (int i = 0 ; i < int(b_vector[index]->entry.size()) ; i++) {
      if (b_vector[index]->entry[i].first == key) {
        f(b_vector[index]->entry[i].second);
        return true;
      }
    }
    return false; 
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @returns true if the key was found and the value unmapped, false otherwise
  bool remove(K key, std::function<void()> on_success) { 
    //generating index from hashing
    int index = std::hash<K>{}(key)%num_buckets;
    //lock guard will release the lock once it goes out of scope
    std::lock_guard<std::mutex> guard(b_vector[index]->lock);
    for (auto i = b_vector[index]->entry.begin(); i != b_vector[index]->entry.end(); i++) {
      if ((*i).first == key) {
        b_vector[index]->entry.erase(i);
        //Code to run if the remove succeeds
        on_success();
        return true;
      }
    }
    //key wasn't found, false
    return false;   
  }

  /// Apply a function to every key/value pair in the ConcurrentHashTable.  Note
  /// that the function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  void do_all_readonly(std::function<void(const K, const V &)> f,
                       std::function<void()> then) {
                         //2 phase locking 
      for (int i=0; i<int(b_vector.size()); i++) {
        b_vector[i]->lock.lock();
        for (int j=0; j<int(b_vector[i]->entry.size()); j++) {
          f(b_vector[i]->entry[j].first, b_vector[i]->entry[j].second);
        }
      }
      //after f, before unlocking
      then();
      //unlocking phase 
      for (int i=0; i<int(b_vector.size()); i++) {
        b_vector[i]->lock.unlock();
      }
  }
};
