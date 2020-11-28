use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, RwLock};

pub struct MultiFileReadWrite<F : Read + Write> {
    rwlock: Arc<RwLock<F>>
}

impl<F : Read + Write> Clone for MultiFileReadWrite<F> {
    fn clone(&self) -> Self {
        Self {
            rwlock: self.rwlock.clone()
        }
    }
}

impl <F : Read + Write> MultiFileReadWrite<F> {

    pub fn new(inner: F) -> Self {
        Self {
            rwlock: Arc::new(RwLock::new(inner))
        }
    }
}

impl MultiFileReadWrite<File> {

    pub fn create_from_path<P : AsRef<Path>>(path: P) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(false)
            .write(true)
            .read(true)
            .open(path)
            .unwrap();
        Self::new(file)
    }
}

impl <F : Read + Write> Read for MultiFileReadWrite<F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self.rwlock.write().unwrap();
        inner.read(buf)
    }
}

impl <F : Read + Write> Write for MultiFileReadWrite<F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.rwlock.write().unwrap();
        inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut inner = self.rwlock.write().unwrap();
        inner.flush()
    }
}

