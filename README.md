# sismo

*Simple, cross-platform tooling to debug your program's performance and
understand what it's doing.*

> [!WARNING]
> **This is a personal playground project, not intended for production
> use.** It's early, very experimental, and expected to change a lot.
>
> - **"sismo" is a codename** and will almost certainly change — don't
>   read anything into the name.
> - It will likely be **upstreamed into
>   [Perfetto](https://github.com/google/perfetto)** at some point, so
>   treat everything here as provisional.

## What?

sismo is an opinionated view on how profiling and tracing should work for
anyone developing applications targeting Linux, Mac or Windows. This
includes CLIs, servers, desktop GUIs etc.

The goal is to give you everything you might need to both debug your app's
performance and understand what it's doing, in many contexts:

```sh
# Run a program and record everything until it exits (or Ctrl-C cuts
# recording short and writes whatever's been captured so far).
sismo record -- ./myapp

# Bounded recording: stop after a fixed duration.
sismo record --duration 5s -- ./myapp

# Flight recorder: continuous ring buffer, snapshot on demand —
# ideal for catching rare events in long-running processes.
sismo record --flight-recorder -- ./myapp
# ...then, from another terminal, capture the current ring buffer
# whenever something interesting happens:
sismo snapshot --output ./incident.pftrace

# Attach to a running process by PID.
sismo record --pid 12345
```

You can then visualize the resulting trace at [ui.perfetto.dev](https://ui.perfetto.dev).
<!-- TODO(lalitm): switch to sismo UI when ready. -->

Concretely, sismo can collect:

* **CPU profiling**: understand where your program is spending time by sampling
  stack traces.
* **Memory profiling**: isolate where your program is allocating too much memory
  or is leaking.
* **App-specific details** (planned): language bindings in C/C++/Rust/Zig/Java/Kotlin/Go
  will let you annotate what your program is doing with rich trees of context.
* **Kernel scheduling**: gain insight into the relationships between threads
  of your process, or how your app might be contending with others on the
  system.

## Why?

In my full time job at Google, I work on [Perfetto](https://github.com/google/perfetto),
a performance profiling and tracing tool. So on the surface, it might seem weird that I'm
developing *another* tool for debugging performance and understanding what your program
is doing in my spare time.

But in my head, Perfetto and sismo play two *very* distinct roles:
* Perfetto is a *platform*: a set of components which can be assembled together
  in many different ways depending on the problem you are tackling. Its power comes from
  flexibility, but it also has a *steep* learning curve. It makes sense to invest if
  you look at performance all the time, but otherwise it can just be too much.
* sismo is a *product*: my opinion on what an average developer needs when they
  start looking at performance. That makes it far less flexible than Perfetto,
  but also far simpler: any engineer should be able to pick it up and start
  being productive within minutes.

These roles aren't in tension with sismo eventually living inside Perfetto: the
most natural home for an opinionated, product-shaped layer is on top of the very
platform it's built from. That's why I expect sismo to be upstreamed into Perfetto
in the future rather than staying a separate project forever.

sismo is more akin to a *Linux distribution*: it picks and chooses which components
from the ecosystem are useful and pulls them together into something coherent.
Concretely, sismo owes a lot to the following tools:
* *Perfetto*: the beating heart of sismo, used at every layer — our recording is
  done using Perfetto tools, our viewer is essentially a soft fork of Perfetto, and
  our analysis layer is PerfettoSQL plus opinionated views on top.
* *samply*: an excellent CPU profiling tool. The libraries that power it are also
  available independently, and power all the CPU profiling and stack inspection
  parts of sismo.
<!-- * TODO(lalitm): once Python/Go bindings are in, we should add it here. -->

## Contributing

sismo is not accepting contributions at this time as it's still under heavy development.
One thing I particularly want to guard against from the start is scope creep:
performance is a complex domain with many moving parts, and there are always unique
solutions or different ideas on what can be done.

It's important to me that sismo stays easy to understand for everyone, so I will
explicitly *not* be accepting first-class support for features I consider too niche.
I'd still be happy to link out to your tool from our docs via the config-file
recording escape hatch.
<!-- TODO(lalitm): document the config-file recording escape hatch once it lands. -->

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This project is built in my personal capacity and is not affiliated with, endorsed
by, or a product of my employer, Google.
