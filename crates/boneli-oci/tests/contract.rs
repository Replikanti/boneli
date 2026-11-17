//! The `ImageStore` contract (ADR-004) on the real adapter over the fake
//! registry: `pull-idempotent`, `missing-image`, `digest-pinned`,
//! `platform-pinned` and `tampered-refused` (#7, ADR-009).

mod support;

use boneli_app::contract::image::{Images, run};
use boneli_app::{ImageError, ImageRef, ImageStore, RootfsRef};
use boneli_oci::OciImageStore;

use support::TempDir;
use support::images::{Layer, open, push};
use support::registry::{Fake, Hub, digest_of};

/// A store on its own root; the root goes with it.
struct Store {
    store: OciImageStore,
    _root: TempDir,
}

impl ImageStore for Store {
    fn pull(&self, image: &ImageRef) -> Result<RootfsRef, ImageError> {
        self.store.pull(image)
    }
}

fn image_ref(name: &str, digest: &str, platform: &str) -> ImageRef {
    ImageRef {
        name: name.to_owned(),
        digest: digest.to_owned(),
        platform: platform.to_owned(),
    }
}

/// The hub: `library/app` for `linux/amd64` under an index, and
/// `library/tampered`, whose layer blob is served with one byte flipped.
/// An unknown repository gets `401` even with a token, as on Docker Hub.
fn images() -> Images<Store> {
    let mut hub = Hub::default();
    let app = push(
        &mut hub,
        "library/app",
        &[Layer::file("etc/app", b"app\n")],
        "",
    );
    let tampered = push(
        &mut hub,
        "library/tampered",
        &[Layer::file("etc/evil", b"evil\n")],
        "",
    );
    let blob = tampered.blobs[0].clone();
    if let Some(bytes) = hub.blobs.get_mut(&blob)
        && let Some(b) = bytes.last_mut()
    {
        *b ^= 1;
    }
    let fake = Fake::new(move |s| hub.handle(s));
    let root = TempDir::new("contract");
    let store = open(&root.path().join("store"), &fake);
    Images {
        adapter: Store { store, _root: root },
        present: image_ref("library/app", &app.index, "linux/amd64"),
        missing: image_ref("library/missing", &app.index, "linux/amd64"),
        other_digest: image_ref("library/app", &digest_of(b"no such index"), "linux/amd64"),
        other_platform: image_ref("library/app", &app.index, "linux/arm64"),
        tampered: image_ref("library/tampered", &tampered.index, "linux/amd64"),
    }
}

#[test]
fn oci_image_store_passes_contract() {
    assert_eq!(run(images), Ok(()));
}

/// The tampered blob never reaches the store: no layer, and no blob
/// under `blobs/sha256/` but the documents.
#[test]
fn tampered_blob_leaves_nothing() {
    let i = images();
    for _ in 0..2 {
        match i.adapter.pull(&i.tampered) {
            Err(ImageError::Failed { detail }) => {
                assert!(detail.contains("does not match its digest"), "{detail}")
            }
            other => panic!("{other:?}"),
        }
    }
    let root = i.adapter.store.root();
    let layers: Vec<_> = std::fs::read_dir(root.join("layers/sha256"))
        .expect("layers")
        .collect();
    assert!(layers.is_empty(), "{layers:?}");
    let blobs = std::fs::read_dir(root.join("blobs/sha256"))
        .expect("blobs")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".type"))
        .count();
    assert_eq!(blobs, 3, "index, manifest and config only");
}
