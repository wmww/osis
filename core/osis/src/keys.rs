//! `DynamicAspectKey`: an aspect key by name, typed by a schema registered at run time (`Osis::aspect_key`), and the
//! core keys apps write. Typed `Aspect<T>` and `Signal<T>` come from codegen (osis-schema).

use osis_base::{Ak, Value};
use osis_schema::{RawKey, Codec, PathError, Schema, typed_read};
use std::sync::Arc;

/// An aspect key made at run time (`Osis::aspect_key`), its values plain `Value`s. Under a registered
/// schema its reads are typed and its writes validated. Its kind (value aspect or signal, the `~`
/// marker) is known only at run time, so it takes both kinds' calls: a read of the other kind
/// reads absent or lists nothing, and a write of the other kind (a value write on a signal,
/// `fire` on a value aspect) fails `commit` with `Invalid`.
#[derive(Clone, Debug)]
pub struct DynamicAspectKey {
    pub(crate) ak: Ak,
    pub(crate) schema: Option<Arc<Schema>>,
}

/// The core schema, one shared copy.
pub(crate) fn core_schema() -> Arc<Schema> {
    static CORE: std::sync::OnceLock<Arc<Schema>> = std::sync::OnceLock::new();
    CORE.get_or_init(|| Arc::new(osis_schema::core_schema().clone())).clone()
}

impl DynamicAspectKey {
    /// The key named `ak` with no schema, even where one is registered: any stored value as it is.
    pub fn untyped(ak: Ak) -> DynamicAspectKey {
        DynamicAspectKey { ak, schema: None }
    }

    /// Its name.
    pub fn name(&self) -> Ak {
        self.ak.clone()
    }

    /// The type of its values, as its schema declares it (`None`: no schema declares it): `get()`
    /// its shape, `name()` its declared name.
    pub fn value_type(&self) -> Option<crate::NestedType> {
        let s = self.schema.clone()?;
        let ty = s.aspects.get(self.ak.as_str())?.ty.clone();
        Some(crate::value_type::nested(s, ty))
    }

    /// Who may purge a write through this key and how long it is held, unless it says otherwise (`AspectWrite::retention`).
    pub fn default_retention(&self) -> crate::Retention {
        self.defaults().retention.into()
    }
}

impl osis_schema::AspectKey for DynamicAspectKey {}
impl osis_schema::ValueKey for DynamicAspectKey {}
impl osis_schema::SignalKey for DynamicAspectKey {}

impl RawKey for DynamicAspectKey {
    type T = Value;
    fn ak(&self) -> &str {
        self.ak.as_str()
    }
    fn schema(&self) -> Option<&Schema> {
        self.schema.as_deref()
    }
    fn shared_schema(&self) -> Option<Arc<Schema>> {
        self.schema.clone()
    }
    fn decode(&self, v: &Value) -> Result<Value, PathError> {
        // `created.0` is typed by its exclusivity rule, not the missing-field rule
        // (spec/data-model.md §9).
        if self.schema.is_some() && self.ak.as_str() == osis_schema::core_types::CREATED.ak() {
            return <osis_base::CreationRecord as Codec>::from_value(v).map(|_| v.clone());
        }
        match (self.schema.as_deref(), self.ty()) {
            (Some(s), Some(t)) => typed_read(s, v, t),
            _ => Ok(v.clone()),
        }
    }
    fn encode(&self, t: &Value) -> Value {
        t.clone()
    }
}

/// Aspects every app shares the meaning of, and what a thing keeps of replaced content.
pub mod core {
    /// What a thing is called.
    pub use osis_schema::core_types::NAME;
    /// A thing's main text.
    pub use osis_schema::core_types::BODY;
    /// Marks a thing as a tag.
    pub use osis_schema::core_types::TAG;
    pub use osis_schema::core_types::Tag;
    pub use crate::retention::{RetentionEntry, RetentionSetting};
    /// What a thing keeps of replaced content, by aspect, and the expiry its writes get. An admin
    /// sets it, at any time.
    pub const RETENTION: osis_schema::Aspect<RetentionSetting> = osis_schema::Aspect::new("retention^.0", &osis_schema::CORE);
}

/// Which calls each key kind takes, checked at compile time: value operations do not compile on
/// a `Signal`, signal operations not on an `Aspect` (a `DynamicAspectKey` takes both, checked
/// at run time). The first test is the same setup taking every allowed call, so each failing
/// one fails for its one forbidden call.
/// ```
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # let keep = osis::core::RetentionEntry { history: Some(osis::History::FOREVER), ..Default::default() };
/// # w.at(t, osis::core::RETENTION).set(&osis::core::RetentionSetting { rules: [(osis::Ak::new("t:ping~0").unwrap(), keep)].into(), ..Default::default() }).unwrap();
/// // what each kind takes
/// w.at(t, N).set(&1).unwrap();
/// w.at(t, N).edit(&1, &2).unwrap();
/// w.at(t, N).overwrite(&1).unwrap();
/// w.at(t, N).path(p![]).set(&1i64).unwrap();
/// w.at(t, N).remove().unwrap();
/// w.commit().unwrap();
/// let mut w = db.write();
/// w.at(t, PING).fire(&1).unwrap();
/// let fire = w.commit().unwrap().unwrap().stamp.id;
/// let mut w = db.write();
/// w.at(t, PING).replace(fire, &2).unwrap();
/// w.commit().unwrap();
/// let _ = db.at(t, N).commit(fire).unwrap();
/// assert!(db.at(t, PING).commit(fire).unwrap().is_some());
/// assert_eq!(db.at(t, PING).versions(fire, &CommitQuery::default()).unwrap().commits.len(), 2);
/// let _ = db.at(t, N).get().unwrap();
/// let _ = db.at(t, N).path(p![]).get::<i64>().unwrap();
/// let _ = db.at(t, N).on_change(|_, _| {}).unwrap();
/// let _ = db.at(t, N).writes(&CommitQuery::default()).unwrap();
/// let _ = db.at(t, N).on_write(|_, _| {}).unwrap();
/// assert_eq!(db.at(t, PING).fired(&CommitQuery::default()).unwrap().commits.len(), 1);
/// let _ = db.at(t, PING).on_fire(|_, _| {}).unwrap();
/// ```
///
/// `get` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, PING).get();
/// ```
///
/// `path` reads on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, PING).path(p![]).get::<i64>();
/// ```
///
/// `on_change` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, PING).on_change(|_, _| {});
/// ```
///
/// `writes` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, PING).writes(&CommitQuery::default());
/// ```
///
/// `on_write` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, PING).on_write(|_, _| {});
/// ```
///
/// `keep_alive` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, PING).keep_alive(&1);
/// ```
///
/// `set` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = w.at(t, PING).set(&1);
/// ```
///
/// `edit` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = w.at(t, PING).edit(&1, &2);
/// ```
///
/// `overwrite` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = w.at(t, PING).overwrite(&1);
/// ```
///
/// `remove` on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = w.at(t, PING).remove();
/// ```
///
/// path writes on a signal:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = w.at(t, PING).path(p![]).set(&1i64);
/// ```
///
/// `fire` on a value key:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = w.at(t, N).fire(&1);
/// ```
///
/// `fired` on a value key:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, N).fired(&CommitQuery::default());
/// ```
///
/// `on_fire` on a value key:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// let _ = db.at(t, N).on_fire(|_, _| {});
/// ```
///
/// `replace` on a value key:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # let id: osis::CommitId = "00".repeat(32).parse().unwrap();
/// let _ = w.at(t, N).replace(id, &1);
/// ```
///
/// `versions` on a value key:
/// ```compile_fail,E0599
/// # use osis::{Config, MemStore, Osis, Store, CommitQuery, p};
/// # static S: osis::generated::StaticSchema = osis::generated::StaticSchema::new("t.osis", "revision 1;\nsignal t:ping~0: int;\naspect t:n.0: int;\n");
/// # const PING: osis::Signal<i64> = osis::Signal::new("t:ping~0", &S);
/// # const N: osis::Aspect<i64> = osis::Aspect::new("t:n.0", &S);
/// # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default()).unwrap();
/// # let mut w = db.write();
/// # let t = w.create().unwrap();
/// # let id: osis::CommitId = "00".repeat(32).parse().unwrap();
/// let _ = db.at(t, N).versions(id, &CommitQuery::default());
/// ```
#[cfg(doctest)]
pub struct KeyKinds;
