#pragma once

#include <cstdio>
#include <string>

#include "../common/vec.h"

/// Atomically add an incremental update message to the open file
///
/// This variant puts three strings into the file, and then an integer with
/// value 0.  This is a somewhat over-specialized function, but it's OK for
/// now.
///
/// @param storage_file The file to write into
/// @param magic The magic 8-byte string that is the start of the message
/// @param s1    The first string to add to the message
/// @param s2    The second string to add to the message
void incremental_persist_2sn(FILE *storage_file, const std::string &magic,
                             const std::string &s1, const std::string &s2);

/// Atomically add an incremental update message to the open file
///
/// This variant puts two strings into the file, and then a vec.
///
/// @param storage_file The file to write into
/// @param magic The magic 8-byte string that is the start of the message
/// @param s1    The string to add to the message
/// @param v1    The vec to add to the message
void incremental_persist_sv(FILE *storage_file, const std::string &magic,
                            const std::string &s1, const vec &v1);

/// Atomically add an incremental update message to the open file
///
/// This variant puts two strings into the file
///
/// @param storage_file The file to write into
/// @param magic The magic 8-byte string that is the start of the message
/// @param s1    The string to add to the message
void incremental_persist_s(FILE *storage_file, const std::string &magic,
                           const std::string &s1);