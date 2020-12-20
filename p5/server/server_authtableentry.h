#pragma once

#include <string>

#include "../common/vec.h"

/// AuthTableEntry represents one user stored in the authentication table
struct AuthTableEntry {
  /// The name of the user; max 64 characters
  std::string username;

  /// The hashed password.  Note that the password is a max of 128 chars
  std::string pass_hash;

  /// The user's content
  vec content;
};
