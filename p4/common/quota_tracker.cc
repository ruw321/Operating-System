// NB: http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <time.h>

#include "quota_tracker.h"

/// quota_tracker::Internal is the class that stores all the members of a
/// quota_tracker object. To avoid pulling too much into the .h file, we are
/// using the PIMPL pattern
/// (https://www.geeksforgeeks.org/pimpl-idiom-in-c-with-examples/)
struct quota_tracker::Internal {
  /// An event is a timestamped amount.  We don't care what the amount
  /// represents, because the code below will only sum the amounts in a
  /// collection of events and compare it against a quota.
  struct event {
    /// The time at which the request was made
    time_t when;

    /// The amount of resource consumed at the above time
    size_t amnt;
  };

  /// The maximum amount of service
  size_t amount;
  /// The time during the service maximum can be spread out
  double duration;
  /// Deque containing user requests
  std::deque<event> events;

  // NB: You probably want to add a few more fields here

  /// Construct the Internal object
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time during the service maximum can be spread out
  Internal(size_t amount, double duration) {
    this->amount = amount;
    this->duration = duration;
  }
};

/// Construct an object that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time during the service maximum can be spread out
quota_tracker::quota_tracker(size_t amount, double duration)
    : fields(new Internal(amount, duration)) {}

/// Construct a quota_tracker from another quota_tracker
///
/// @param other The quota tracker to use to build a new quota tracker
quota_tracker::quota_tracker(const quota_tracker &other) 
    : fields(new Internal(other.fields->amount, other.fields->duration)) {}

/// Destruct a quota tracker
quota_tracker::~quota_tracker() = default;

/// Decides if a new event is permitted.  The attempt is allowed if it could
/// be added to events, while ensuring that the sum of amounts for all events
/// with (time > now-q_dur), is less than q_amnt.
///
/// @param amount The amount of the new request
///
/// @returns True if the amount could be added without violating the quota
bool quota_tracker::check(size_t amount) { 

  size_t sum_amount = 0;
  time_t now = time(NULL);

  for(size_t i = 0; i < fields->events.size(); i++) {
    if(fields->duration > difftime(now, fields->events[i].when)) {
      sum_amount += fields->events[i].amnt;
    }
  }
  return (sum_amount + amount) <= fields->amount; 
}

/// Actually add a new event to the quota tracker
void quota_tracker::add(size_t amount) {
  fields->events.push_back({time(NULL), amount});
}