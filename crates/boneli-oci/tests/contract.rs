//! The `ImageStore` contract (ADR-004) on the real adapter over the fake
//! registry: `pull-idempotent`, `missing-image`, `digest-pinned`,
//! `platform-pinned` and `tampered-refused` (#7, ADR-009), and
//! `agent-origin-refused` and `exemption-reported` (ADR-032).

mod support;

use boneli_app::contract::image::{Images, run};
use boneli_app::{ImageError, ImageOrigin, ImageRef, ImageStore, Pulled};
use boneli_oci::{AgentExemption, ExemptScope, OciImageStore, SignaturePolicy};

use support::TempDir;
use support::images::{Layer, config, push};
use support::registry::{Fake, Hub, digest_of};

/// A store on its own root; the root goes with it.
struct Store {
    store: OciImageStore,
    _root: TempDir,
}

impl ImageStore for Store {
    fn pull(&self, image: &ImageRef) -> Result<Pulled, ImageError> {
        self.store.pull(image)
    }
}

fn image_ref(name: &str, digest: &str, platform: &str) -> ImageRef {
    ImageRef {
        name: name.to_owned(),
        digest: digest.to_owned(),
        platform: platform.to_owned(),
        origin: ImageOrigin::Operator,
    }
}

fn agent(image: ImageRef) -> ImageRef {
    ImageRef {
        origin: ImageOrigin::Agent,
        ..image
    }
}

/// The hub: `library/app` for `linux/amd64` under an index,
/// `library/tampered`, whose layer blob is served with one byte flipped,
/// and `library/exempt`, which the store's one agent exemption names
/// exactly; the unsigned `library/app` is the agent's refused image. An
/// unknown repository gets `401` even with a token, as on Docker Hub.
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
    let exempt = push(
        &mut hub,
        "library/exempt",
        &[Layer::file("etc/exempt", b"exempt\n")],
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
    let mut config = config(&fake);
    config.signatures = SignaturePolicy::off()
        .with_agent_exemptions(vec![AgentExemption {
            registry: "docker.io".to_owned(),
            scope: ExemptScope::parse("library/exempt").expect("scope"),
        }])
        .expect("policy");
    let store = OciImageStore::open(&root.path().join("store"), config).expect("open");
    Images {
        adapter: Store { store, _root: root },
        present: image_ref("library/app", &app.index, "linux/amd64"),
        missing: image_ref("library/missing", &app.index, "linux/amd64"),
        other_digest: image_ref("library/app", &digest_of(b"no such index"), "linux/amd64"),
        other_platform: image_ref("library/app", &app.index, "linux/arm64"),
        tampered: image_ref("library/tampered", &tampered.index, "linux/amd64"),
        agent_refused: agent(image_ref("library/app", &app.index, "linux/amd64")),
        agent_exempted: agent(image_ref("library/exempt", &exempt.index, "linux/amd64")),
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
