use std::path::Path;

use anyhow::Result;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

pub const IGNORE_FILE: &str = ".keyscanignore";

pub struct Skip(Option<Gitignore>);

impl Skip {
    pub fn load(base: &Path) -> Result<Self> {
        let path = base.join(IGNORE_FILE);
        if !path.is_file() {
            return Ok(Skip(None));
        }
        let mut builder = GitignoreBuilder::new(base);
        if let Some(err) = builder.add(&path) {
            return Err(err.into());
        }
        Ok(Skip(Some(builder.build()?)))
    }

    pub fn skips(&self, rel: &str) -> bool {
        match &self.0 {
            Some(g) => g
                .matched_path_or_any_parents(Path::new(rel), false)
                .is_ignore(),
            None => false,
        }
    }
}
