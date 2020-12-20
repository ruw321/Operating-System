#pragma once

#include "../common/quota_tracker.h"

/// Quotas holds all of the quotas associated with a user
struct Quotas {
  /// The user's upload quota
  quota_tracker uploads;

  /// The user's download quota
  quota_tracker downloads;

  /// The user's requests quota
  quota_tracker requests;
};
