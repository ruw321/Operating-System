# Assignment #3: Adding Incremental Persistence

The purpose of this assignment is to gain experience with nuanced code for
persistence.

## Assignment Details

In the last assignment, we added a lot of new functionality to our server.
However, our persistence strategy was still somewhat unrealistic.  The way we
should think about persistence is "if persistence is important, then it needs to
be done well".

What does it mean to do persistence "well", though?  Certainly we don't want to
write the entire Storage object to disk every time it changes.  But how do we
know when a change is so important that it needs to be persisted *right away*?

Our solution will be to extend our storage file format: in addition to being
able to hold the entire state of the Storage object, it will now also be able to
hold "diffs".  A "diff" will be a small message, appended to the end of the
file, that describes a change that should be made to the Storage.

As an example, suppose that the directory had the key "k1" with the value "v1".
If a client performed an upsert to change the value to "v2", we would **not**
modify the representation of "v1" in the file.  Instead, we would add a message
of the form "KVNEWVAL".sizeof("k1")."k1".sizeof("v2")."v2".  We could also have
messages to indicate that a key is deleted, or that a user's content changed.
For details about the new log messages, see `server/server_storage.h`.

Making this work is challenging: we need to ensure that any update to the data
file is consistent with the state of the object in memory.  So, for example, if
two server threads are simultaneously adding keys "k1" and "k2", then their
"KVNEWVAL" messages should not be interleaved.  In addition, if one thread
inserts "k1" and then another deletes "k1", the order of the add and delete
messages should be the same as the order in which threads performed their
operations.

If we want to be efficient, then it is not wise to have threads constantly open
and close the file... we will need to keep it open, perform appends to it, and
use `fflush()` to ensure that data reaches the disk.  Note: in real servers,
read-only operations far exceed all other operations, so we shouldn't worry that
disk writes will be too frequent.

Our server will still support the "SAV" command, which will produce an optimal
representation of the Storage object (that is, `persist()` doesn't change!). But
now `load()` will need to be able to handle the case where there are diff
records at the end of the file, and any operation that modifies the Storage
object will need to append to the file.  (If you're thinking "most of my work
will be in `server/storage.h`", you're right... there's just a small change to
`common/hashtable.h`.)

## Getting Started

Your git repository has a new folder, `p3`, which includes binary files that
represent some of the solution to assignment 2.  The Makefile has been updated
so that you do not need to have completed the first assignment or the thread
pool from the second assignment in order to get full credit for this assignment.

There is a test script called `tests/p3.py`, which you can use to test your
code.  Note that these tests are not sufficient to show that your code is
thread-safe and free of data races.  We will inspect your code to evaluate its
correctness in the face of concurrency.

## Tips and Reminders

Your first step should be to copy your hashtable solution from `p2`, taking care
to not change the (new) signatures for the hashtable methods.  You will also
want to copy your `server_storage.cc` implementation from `p2`.

Next, you should probably try to tackle an individual diff message, and get it
to work in `load()`.  Once you have figured out one, the others should not be
too hard.  But the synchronization and atomicity will be tricky.  Do not
underestimate the time it will take to produce a correct solution.

As in the last assignment, you should keep in mind that subsequent assignments
will build upon this... so as you craft a solution, be sure to think about how
to make it maintainable.

**Start Early**.  Just reading the code and understanding what is happening
takes time.  If you start reading the assignment early, you'll give yourself
time to think about what is supposed to be happening, and that will help you to
figure out what you will need to do.

As always, please be careful about not committing unnecessary files into your
repository.

Your programs should never require keyboard input. In particular, the client
should get all its parameters from the command line, and usually it rely on
files for getting and storing data.

Your server should **not** store plain-text passwords in the file.

You will notice that there were changes to the signatures of several of the
methods of the concurrent hash table.  This was intentional: by allowing a
lambda to run while locks are held, it is easier to ensure 2pl.  Remember: you
should make sure that your code obeys 2pl so that it is easy to argue its
correctness.

## Grading

If the script passes, then you will receive full "functionality" points.  We
will manually inspect your code to determine if it is correct with regard to
atomicity.  As before, we reserve the right to deduct "style" points if your
code is especially convoluted.  Please be sure to use your tools well.  For
example, Visual Studio Code (and emacs, and vim) have features that auto-format
your code.  You should use these features.

There are two main gradeable portions of the assignment:

* Does the server write incrementally to the file, and handle diffs when
  loading?
* Is the interaction with files correct (atomic, consistent)?

## Notes About the Reference Solution

Let's use `insert` as an example to illustrate some important issues about the
interaction between persistence and concurrency.  Suppose that two threads are
inserting two different k/v pairs at the same time... does it matter which order
they appear in the log?  Probably not.  But suppose that two threads are
upserting two different values for the same key at the same time... now it does
matter which order they appear in the log.

From the above, you should recognize that we are going to have to do some amount
of writing to a file *while holding a single bucket's lock*.  That is, this
isn't going to be like the implementation of `persist()`, where we needed to use
2pl on the entire table, but it's also not like the first assignment where we
didn't care much about atomicity.

One thing that works to our advantage is that a single `write()` syscall *will
be atomic*.  But how do we get our writes to happen while holding locks?  The
answer, as you have probably guessed, is lambdas.  Most of the functions in
`hashtable.h` now take an extra lambda (or two!).  Including comments, the
solution for `hashtable.h` should only be about 12 lines longer than the
solution in assignment 2.

The `server_storage.h` implementation is where most of the work will be.  The
reference solution grew by about 180 lines, relative to assignment 2.  In
particular, `load()` will grow to about 170 lines of code, in order to handle
all of the new entry types that are possible in the file.

