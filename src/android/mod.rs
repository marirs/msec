//! Android package analysis.

mod apk;
mod chunk;
mod generated;
pub mod inventory;
pub mod manifest;
pub mod permissions;
pub mod resources;
pub mod sdk;
mod string_pool;
pub mod value;
pub mod xml;

pub use apk::Apk;
pub use chunk::ChunkProblem;
pub use inventory::Inventory;
pub use manifest::Manifest;
pub use resources::ResourceTable;
pub use string_pool::StringPoolProblem;
pub use value::Value;
pub use xml::XmlDocument;
