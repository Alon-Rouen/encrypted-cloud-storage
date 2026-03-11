use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEntry {
    pub storage_id: String,
    pub size: u64,
    pub uploaded_at: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Manifest {
    pub version: u64,
    pub files: HashMap<String, FileEntry>,
}

impl Manifest {
    pub fn new() -> Self {
        Manifest { version: 0, files: HashMap::new() }
    }
    pub fn upsert(&mut self, filename: &str, entry: FileEntry) {
        self.version += 1;
        self.files.insert(filename.to_string(), entry);
    }
    pub fn remove(&mut self, filename: &str) -> bool {
        if self.files.remove(filename).is_some() {
            self.version += 1;
            true
        } else {
            false
        }
    }
    pub fn get(&self, filename: &str) -> Option<&FileEntry> {
        self.files.get(filename)
    }
    pub fn list_files(&self) -> Vec<&String> {
        let mut names: Vec<&String> = self.files.keys().collect();
        names.sort();
        names
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dummy_entry(id: &str) -> FileEntry {
        FileEntry { storage_id: id.to_string(), size: 42, uploaded_at: 0 }
    }
    #[test]
    fn upsert_increments_version() {
        let mut m = Manifest::new();
        m.upsert("a.txt", dummy_entry("uuid-1"));
        assert_eq!(m.version, 1);
    }
    #[test]
    fn remove_returns_false_for_missing_file() {
        let mut m = Manifest::new();
        assert!(!m.remove("nonexistent.txt"));
        assert_eq!(m.version, 0);
    }
    #[test]
    fn list_files_is_sorted() {
        let mut m = Manifest::new();
        m.upsert("z.txt", dummy_entry("1"));
        m.upsert("a.txt", dummy_entry("2"));
        m.upsert("m.txt", dummy_entry("3"));
        let list = m.list_files();
        assert_eq!(list, vec!["a.txt", "m.txt", "z.txt"]);
    }
}
