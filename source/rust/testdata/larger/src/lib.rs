mod base_plugin;
mod extract_plugin;
mod parse_plugin;
mod parsers;
mod proto;
mod source_plugin;
mod threadstate;

use falco_plugin::{extract_plugin, parse_plugin, plugin, source_plugin};

use base_plugin::{EderaPlugin, EderaZoneSyscallContext};

// For each "kind" of plugin, we have to run the following macros
// once-per-crate against a type with the correct impls, so
// do all of them here.
plugin!(EderaPlugin); // base_plugin (shared by all others)
source_plugin!(EderaPlugin);
parse_plugin!(EderaPlugin);
extract_plugin!(EderaPlugin);
