<p align="center">
  <img src="https://raw.githubusercontent.com/zeskeertwee/virtfs-rs/main/media/logo.png" alt=".vach logo" width="180" height="180">
</p>
<h1 align=center>
  <strong>vach</strong>
</h1>
<p align=center> A simple archiving format, designed for storing assets in compact secure containers </p>
<p align=center>
  <a href="https://docs.rs/vach"><img alt="docs.rs" src="https://img.shields.io/docsrs/vach?style=flat-square"></a> |
  <a href="https://crates.io/crates/vach"><img alt="Crate Version on Crates.io" src="https://img.shields.io/crates/v/vach?style=flat-square"></a> |
  <a href="https://github.com/zeskeertwee/virtfs-rs/blob/main/LICENSE"><img alt="LISCENCE: GPL 2.0" src="https://img.shields.io/crates/l/vach?style=flat-square"></a> |
  <a href="https://github.com/zeskeertwee/virtfs-rs/actions/workflows/rust.yml"><img alt="GitHub Build and Test actions" src="https://github.com/zeskeertwee/virtfs-rs/workflows/Rust/badge.svg"></a> |
  <a href="https://github.com/zeskeertwee/virtfs-rs/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues-raw/zeskeertwee/virtfs-rs?style=flat-square"></a>
</p>
<p align=center>
 <a href="https://docs.rs/vach">Docs</a> | <a href="https://github.com/zeskeertwee/virtfs-rs">Repo</a>
</p>

## 👔 The official `vach` and `vf` crates' repo

`vach`, pronounced like "fuck" but with a "v", is a archiving and resource transmission format. It was built to be secure, contained and protected ( _once encryption is implemented_ ). It was, in fact, designed by the [SCP](https://en.wikipedia.org/wiki/SCP_Foundation) to keep your anomalous assets compact and secure during transmission. `vach` also has in-built support for [compression](https://github.com/PSeitz/lz4_flex), [data signing](https://github.com/dalek-cryptography/ed25519-dalek), leaf [bitflags](https://docs.rs/vach/0.1.5/vach/prelude/struct.Flags.html#) and archive customization. Check out the `vach` spec at **[spec.txt](https://github.com/zeskeertwee/virtfs-rs/blob/main/spec/main.txt)**. Any and *all* help will be much appreciated, especially proof reading the docs and code review.

---

### 👄 Terminologies

- **Archive:** Any source of data, for example a file or TCP stream, that is a valid `vach` data source.
- **Leaf:** Any actual data endpoint within an archive, for example `footstep1.wav` in `sounds.vach`.
- **Entry:** Some data in the registry section of a `vach` source on an corresponding `leaf`. For example, `{ id: footstep.wav, location: 45, offset: 2345, flags: 0b0000_0000_0000_0000u16 }`.

---

### 🀄 Show me some code _dang it!_

##### > Building a basic unsigned `.vach` file

```rust
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig};

let config = BuilderConfig::default();
let mut builder = Builder::default();

// Use `Builder::add( reader, ID )` to add data to the write queue
// builder.add(File::open("test_data/background.wav")?, "ambient");
// builder.add(File::open("test_data/footstep.wav")?, "ftstep");
builder.add(Cursor::new(b"Hello, Cassandra!"), "hello");

// let mut target = File::create("sounds.vach")?;
let mut target = Cursor::new(Vec::new());

// The number of bytes written to the file
let size = builder.dump(&mut target, &config).unwrap();
```

##### > Loading resources from an unsigned `.vach` file

```rust
use std::fs::File;
use vach::prelude::{Archive, Resource, Flags};

let target = File::open("sounds.vach")?;
let mut archive = Archive::from_handle(target)?;
let resource: Resource = archive.fetch("ambient")?;

// By default all resources are flagged as NOT secured
println!("{}", Sound::new(&resource.data)?);
assert!(!resource.secured);

let mut buffer = Vec::new();
let (flags, content_version, is_secure) = archive.fetch_write("ftstep", &mut buffer)?;
```

##### > Build a signed `.vach` file

```rust
use std::{io::Cursor, fs::File};
use vach::prelude::{Builder, BuilderConfig, Keypair};
use vach::utils::gen_keypair;

let keypair: Keypair = gen_keypair();
let config: BuilderConfig = BuilderConfig::default().keypair(keypair);
let mut builder = Builder::default();

// Use `Builder::add( reader, ID )` to add data to the write queue
// builder.add(File::open("test_data/background.wav")?, "ambient");
// builder.add(File::open("test_data/footstep.wav")?, "ftstep");
builder.add(Cursor::new(b"Hello, Cassandra!"), "hello");

// let mut target = File::create("sounds.vach")?;
let mut target = Cursor::new(Vec::new());

builder.dump(&mut target, &config).unwrap();
```

##### > Serialize and de-serialize a `Keypair`, `SecretKey` and `PublicKey`

As `Keypair`, `SecretKey` and `PublicKey` are reflected from [ed25519_dalek](https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/), you could refer to their docs to read further about them.

```rust
use vach;
use vach::prelude::{Keypair, SecretKey, PublicKey};
use vach::utils::gen_keypair;

// Generate keys
let keypair : Keypair  = gen_keypair();
let secret : SecretKey = keypair.secret;
let public : PublicKey = keypair.public;

// Serialize
let public_key_bytes : [u8; vach::PUBLIC_KEY_LENGTH] = public.to_bytes();
let secret_key_bytes : [u8; vach::SECRET_KEY_LENGTH] = secret.to_bytes();
// let keypair_bytes : [u8; vach::KEYPAIR_LENGTH]    = keypair.to_bytes();

// Deserialize
let public_key : PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
let secret_key : SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
// let keypair : Keypair   = Keypair::from_bytes(&keypair_bytes).unwrap();
```

##### > Load resources from a signed `.vach` source

```rust
// Load public_key
let mut public_key = File::open(PUBLIC_KEY)?;
let mut public_key_bytes: [u8; crate::PUBLIC_KEY_LENGTH];
public_key.read_exact(&mut public_key_bytes)?;

// Build the Loader config
let mut config = HeaderConfig::default().key(PublicKey::from_bytes(&public_key_bytes)?);

let target = File::open("sounds.vach")?;
let mut archive = Archive::with_config(target, &config)?;

// Resources are marked as secure (=true) if the signatures match the data
let resource = archive.fetch("ambient")?;
println!("{}", Sound::new(&resource.data)?);
assert!(resource.secured);
```

> For more information on how to use the library, read the documentation. [Always read the documentation!](https://youtu.be/TUE_HSgQiG0?t=91) And pass by the examples folder( not yet implemented ).

---

### 🛠 Yet to be implemented

- [ ] An official **CLI**.
- [ ] Data encryption.
- [ ] Skynet, (coming very soon).
- [ ] `Some(examples)` directory instead of `None`
