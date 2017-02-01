binpatch
========

A simple tool for patching the code of running binaries.
Suggestion to write such a tool due to [Max Justicz](https://github.com/justicz).

**WARNING:** This tool isn't useful yet!
It doesn't handle inter-symbol references correctly yet, and thus crashes in basically any non-trivial example.
Further, there exist race conditions, as currently binpatch doesn't carefully check what state the target is in when it attaches.
The goal is to make it work better eventually; feel free to submit pull requests.

Example usage
-------------

First, make the example:

    make -C examples

There will be a simple program in there that counts up:

    $ ./examples/counter
    My pid: 12345
    Value: 1
    Value: 2
    Value: 3
    ^C

This program has a function `int func(int x)` that returns `x + 1`, which is used for the counting.
There's another program, `examples/counter_new` which was compiled from the same source, except a macro is defined making `func(x)` return `x + 2`, and thus this binary counts by twos:

    $ ./examples/counter
    My pid: 12346
    Value: 2
    Value: 4
    Value: 6
    ^C

Our goal is to launch `examples/counter`, and replace the code of its `func()` in the running binary with that from `examples/counter_new`.

To accomplish this we first produce a *migration* file as follows:

    $ ./binpatch.py --old examples/counter --new examples/counter_new -o migration1
    Updated symbol: func
    $ cat migration1
    write 400596 VUiJ5Yl9/INF/AKLRfxdww==

You can then apply this migration to a running `examples/counter` process with:

    $ ./binpatch --apply migration1 --pid PID

If the above fails (especially on Ubuntu) it may be because of hardening that blocks processes from ptracing non-children.
You can either run binpatch as root, or disable this protection with:

    $ echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

Here's an all-in-one example:

    $ ./examples/counter & PID=$!; sleep 3; ./binpatch.py --apply migration1 --pid $PID; fg
    [1] 14597
    My pid: 14597
    Value: 1
    Value: 2
    Value: 3
    Value: 4
    === Parsing migration
    Writing 16 bytes to 400596
    Compiled 1 commands.

    === Attaching to 14597
    Attached.
    Writing to 400596
    Detached.
    ./examples/counter
    Value: 6
    Value: 8
    Value: 10
    Value: 12
    ...

Here we start `examples/counter`, then sleep three seconds, during which it counts 1, 2, 3, 4.
Then binpatch applies our migration, updating `func()` to the new "`return x + 2;`" version.
We can see that the running program is immediately updated, as it begins counting by twos.

License
-------

This entire project is licensed under CC0 (that is, public domain), so you are free to do whatever you wish with it.
