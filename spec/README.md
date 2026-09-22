# Overview
osis (Open Structured Information System) is a decentralized database optimized for flexibility and robustness. It's designed to be usable for a wide variety of applications, but particularly end-user apps that manage small amounts of interconnected data across users and devices (notes, calendars, spreadsheets, etc). osis is designed to allow multiple apps, versions of apps, generic tools and AI agents to access the same data, like traditional file formats. It also handles syncing data between devices, sharing data between users, encryption, and provides simple APIs for accessing/manipulating data. In softwarespace it sits somewhere between Git, Obsidian, Google Drive and Syncthing.

## API
The osis Rust API allows applications to search, read and write and listen for changes in osis data. It hides the gory details of crypto, databases, networking and CRDTs as well as possible, so apps can focus on their own functionality.

For more details, see [api.md](api.md).

## Data Model
Each piece of osis data is an `Aspect` of a `Thing`. Things are identified by randomly generated 120-bit thing IDs (`tid`s) and aspects are identified by a tid + an aspect key (`AK`). The textual representation of a tid is 20-character base-64 URL string. AKs are identifiers with slashes between components, and specify an aspect's type and meaning. Each aspect has a value, the actual data. Values are enforced to be the correct type for their aspect.

For more details, see [data.md](data.md).

## Permissions
An `Actor` may control multiple `Node`s. A node is an instance of osis running on a device, and an actor is like a user. Actors are cryptographically identified and verified (since there's no centralized server for authentication). Permissions are managed on a per-thing basis. Each thing is owned by exactly one actor at one time, but ownership may be transferred and read/edit permissions may be granted to additional actors.

For more details, see [permissions.md](permissions.md).

## Sync
Each node tracks its own set of things, and syncs with other nodes with overlapping sets. Changes to one or more aspects of one or more things are grouped into commits, which are sent to nodes tracking the affected things and atomically applied. CRDTs are used to automatically resolve conflicts.

For more details, see [sync.md](sync.md).

## Invariants
- There is no single registry of things, the total number of things may exceed what can be tracked by any one system
- There exist groups of things (see [data.md](data.md)), but things may belong to several groups - there is no concept like a "repo"
- osis data may be permanently deleted or modified. The system does not depend on retaining full history.
- Data serializes to a single canonical format, which is byte-identical (for hash stability) when re-encoded across platforms and versions
- BLAKE3 is always used for hashing
