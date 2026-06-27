# Knight Online Rust Server Rewrite

A fork of [OpenKO/KnightOnline](https://github.com/Open-KO/KnightOnline) with the long-term goal of rewriting all server components from C++ to Rust while maintaining full compatibility with the 1.298 client and wire protocol.

> **Status:** Early development. The Login Server (formerly VersionManager) is the first component being rewritten. The remaining C++ servers (AIServer, Ebenezer, Aujard) run unchanged alongside it.

## What this fork changes

The original OpenKO project faithfully reconstructs the Knight Online 1.298 client and server in C++. This fork keeps the client and tools untouched but incrementally replaces the server executables with Rust implementations that speak the same binary protocol. The client can't tell the difference.

### Rewrite progress

| Component | Original | Status |
|-----------|----------|--------|
| Login Server (VersionManager) | C++ | In testing (Rust) |
| AIServer | C++ | Not started |
| Ebenezer | C++ | Not started |
| Aujard | C++ | Not started |

### Why Rust?

This project serves two purposes: learning Rust through a real, non-trivial networked application and eventually producing a server stack that benefits from Rust's memory safety, performance and concurrency model. An MMORPG server is an ideal learning project because it touches TCP networking, binary protocol parsing, database access, concurrent state management and more.

## Project structure

```
KnightOnline/
  src/                          C++ source (client, server, tools), unchanged from OpenKO
  rust/
    login-server/               Rust rewrite of VersionManager
      src/main.rs
      Cargo.toml
  All.slnx, Server.slnx, ...   Visual Studio solutions for the C++ components
```

The C++ and Rust parts are completely independent with separate build systems, separate executables and no FFI or linking between them. At runtime they are just processes that communicate over TCP, same as the original architecture.

## Building and running

### C++ servers (AIServer, Ebenezer, Aujard)

Built with Visual Studio using the existing solution files. See the original setup guides:

- [Windows Project Setup](https://github.com/Open-KO/KnightOnline/wiki/Project-Setup-(Windows))
- [Linux Project Setup](https://github.com/Open-KO/KnightOnline/wiki/Project-Setup-(Linux))

### Rust Login Server

Requires the [Rust toolchain](https://rustup.rs/).

```
cd rust/login-server
cargo run              # development build
cargo build --release  # optimized build, output at target/release/login-server.exe
```

The Login Server listens on TCP port 15100 and handles client version checking, patching, authentication, server list and login-screen news.

### Running everything together

Launch the three C++ servers (AIServer, Ebenezer, Aujard) from Visual Studio as usual and run the Rust Login Server separately. The client connects to port 15100 and interacts with it exactly as it would with the original C++ VersionManager.

## Credits

This project is built on top of [OpenKO](https://github.com/Open-KO/KnightOnline), an open source reconstruction of the Knight Online 1.298 MMORPG. All credit for the original reverse engineering, C++ codebase, client restoration (DirectX 9 upgrade, file format support, tooling) and database schema goes to the OpenKO team and its contributors.

OpenKO was started to learn how the MMORPG Knight Online works, covering areas like TCP/IP networking, SQL Server, performance tuning, 3D graphics, animation and load balancing. This fork shares that learning spirit, extending it into the Rust ecosystem.

If you're interested in the original C++ project or want to contribute to the faithful 1.298 reconstruction, visit the [OpenKO repository](https://github.com/Open-KO/KnightOnline) and their [Discord](https://discord.gg/Uy73SMMjWS).

## License

See [LICENSE](LICENSE) (inherited from OpenKO).
