//! Android package analysis.

pub mod analysis;
pub mod api;
mod apk;
pub mod backup;
pub mod bundle;
mod chunk;
pub mod dex;
mod generated;
pub mod inventory;
pub mod manifest;
pub mod native;
pub mod permissions;
pub(crate) mod proto;
mod proto_resources;
mod proto_xml;
pub mod resources;
pub mod sdk;
pub mod signing;
mod string_pool;
pub mod value;
pub mod xml;

pub use apk::Apk;
pub use bundle::Bundle;
pub use chunk::ChunkProblem;
pub use inventory::Inventory;
pub use manifest::Manifest;
pub use resources::ResourceTable;
pub use string_pool::StringPoolProblem;
pub use value::Value;
pub use xml::XmlDocument;
