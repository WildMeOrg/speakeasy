//! MLS group handling on top of OpenMLS. All state lives in memory.

use openmls::prelude::{tls_codec::*, *};
use openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use uuid::Uuid;

use crate::crypto::fingerprint;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const INVITE_PSK_ID: &[u8] = b"speakeasy/v1/invite";

fn invite_psk() -> Psk {
    Psk::External(ExternalPsk::new(INVITE_PSK_ID.to_vec()))
}

fn err(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

/// A participant's long-lived (for this room) signing identity. Kept across
/// a rejoin so OpenMLS replaces the old leaf instead of adding a second one.
#[derive(Clone)]
pub struct Keys {
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Keys {
    /// `name` is self-asserted. Nothing verifies it.
    pub fn new(name: &str) -> Self {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Keys { signer, credential }
    }

    /// The code other members see next to this participant's name.
    pub fn key(&self) -> String {
        fingerprint(self.signer.public())
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Peer {
    pub name: String,
    pub key: String,
}

fn peer(credential: &Credential, signature_key: &[u8]) -> Peer {
    let name = BasicCredential::try_from(credential.clone())
        .map(|c| String::from_utf8_lossy(c.identity()).into_owned())
        .unwrap_or_else(|_| "?".into());
    Peer {
        name,
        key: fingerprint(signature_key),
    }
}

pub struct Mls {
    provider: OpenMlsRustCrypto,
    keys: Keys,
    group: MlsGroup,
}

impl Mls {
    fn provider(psk: &[u8]) -> Result<OpenMlsRustCrypto, String> {
        let provider = OpenMlsRustCrypto::default();
        PreSharedKeyId::new(CIPHERSUITE, provider.rand(), invite_psk())
            .map_err(err)?
            .store(&provider, psk)
            .map_err(err)?;
        Ok(provider)
    }

    /// First-member bootstrap. The MLS group id is the room id.
    pub fn create(keys: &Keys, room: &Uuid, psk: &[u8]) -> Result<Self, String> {
        let provider = Self::provider(psk)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &keys.signer,
            &config,
            GroupId::from_slice(room.as_bytes()),
            keys.credential.clone(),
        )
        .map_err(err)?;
        Ok(Mls {
            provider,
            keys: keys.clone(),
            group,
        })
    }

    /// Build an external commit that presents the invitation PSK. The result
    /// is provisional: it only counts once the relay has sequenced exactly
    /// this commit. Returns the group and the commit bytes.
    pub fn join(
        keys: &Keys,
        room: &Uuid,
        psk: &[u8],
        group_info: &[u8],
    ) -> Result<(Self, Vec<u8>), String> {
        Self::join_presenting(keys, room, psk, group_info, Some(invite_psk()))
    }

    /// `present` is what the commit claims as its PSK. Anything other than
    /// the invitation PSK exists only so tests can build joins that members
    /// must reject.
    fn join_presenting(
        keys: &Keys,
        room: &Uuid,
        psk: &[u8],
        group_info: &[u8],
        present: Option<Psk>,
    ) -> Result<(Self, Vec<u8>), String> {
        let provider = Self::provider(psk)?;
        let vgi = match MlsMessageIn::tls_deserialize_exact(group_info)
            .map_err(err)?
            .extract()
        {
            MlsMessageBodyIn::GroupInfo(vgi) => vgi,
            _ => return Err("not a group info".into()),
        };
        let mut proposals = Vec::new();
        if let Some(present) = present {
            let id = PreSharedKeyId::new(CIPHERSUITE, provider.rand(), present).map_err(err)?;
            if *id.psk() != invite_psk() {
                id.store(&provider, psk).map_err(err)?; // tests only
            }
            proposals.push(PreSharedKeyProposal::new(id));
        }
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_config(
                MlsGroupJoinConfig::builder()
                    .use_ratchet_tree_extension(true)
                    .build(),
            )
            .build_group(&provider, vgi, keys.credential.clone())
            .map_err(err)?
            .add_psk_proposals(proposals)
            .load_psks(provider.storage())
            .map_err(err)?
            .build(provider.rand(), provider.crypto(), &keys.signer, |_| true)
            .map_err(err)?
            .finalize(&provider)
            .map_err(err)?;
        // Pin the group to the room named in the invitation.
        if group.group_id().as_slice() != room.as_bytes() {
            return Err("group info is for a different room".into());
        }
        let commit = bundle.into_commit().tls_serialize_detached().map_err(err)?;
        Ok((
            Mls {
                provider,
                keys: keys.clone(),
                group,
            },
            commit,
        ))
    }

    /// Public group state a future joiner needs, as of the current epoch.
    pub fn group_info(&self) -> Result<Vec<u8>, String> {
        self.group
            .export_group_info(self.provider.crypto(), &self.keys.signer, true)
            .map_err(err)?
            .tls_serialize_detached()
            .map_err(err)
    }

    pub fn encrypt(&mut self, text: &[u8]) -> Result<Vec<u8>, String> {
        self.group
            .create_message(&self.provider, &self.keys.signer, text)
            .map_err(err)?
            .tls_serialize_detached()
            .map_err(err)
    }

    pub fn members(&self) -> Vec<Peer> {
        self.group
            .members()
            .map(|m| peer(&m.credential, &m.signature_key))
            .collect()
    }

    fn parse(bytes: &[u8], expect: ContentType) -> Result<ProtocolMessage, String> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(err)?
            .try_into_protocol_message()
            .map_err(err)?;
        // Checked before OpenMLS touches the group: an application frame
        // must never be able to reach the code that merges commits.
        if msg.content_type() != expect {
            return Err(format!("expected {expect:?}, got {:?}", msg.content_type()));
        }
        Ok(msg)
    }

    /// Decrypt an application message from another member.
    pub fn process_app(&mut self, bytes: &[u8]) -> Result<(Peer, Vec<u8>), String> {
        let msg = Self::parse(bytes, ContentType::Application)?;
        let processed = self
            .group
            .process_message(&self.provider, msg)
            .map_err(err)?;
        let Sender::Member(index) = *processed.sender() else {
            return Err("application message from a non-member".into());
        };
        let from = self
            .group
            .member_at(index)
            .map(|m| peer(&m.credential, &m.signature_key))
            .ok_or("sender is not in the group")?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok((from, m.into_bytes())),
            _ => Err("not an application message".into()),
        }
    }

    /// Admit a joiner. The only commits a room has are external joins.
    ///
    /// Admission rules (ours, not OpenMLS's):
    /// - the commit must come from a non-member and carry a PSK proposal
    ///   naming the invitation PSK; OpenMLS then proves the PSK value
    ///   through the confirmation tag;
    /// - it must not remove us: OpenMLS stages such a commit without
    ///   deriving the epoch, so the PSK would go unverified;
    /// - it may remove only a leaf with the joiner's own signing key, which
    ///   is how a member that missed messages replaces its old self.
    pub fn process_join(&mut self, bytes: &[u8]) -> Result<Peer, String> {
        let msg = Self::parse(bytes, ContentType::Commit)?;
        let processed = self
            .group
            .process_message(&self.provider, msg)
            .map_err(err)?;
        if !matches!(processed.sender(), Sender::NewMemberCommit) {
            return Err("only joins are expected as commits".into());
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err("not a commit".into());
        };
        if staged.self_removed() {
            return Err("join tried to remove this member".into());
        }
        if !carries_invite_psk(&staged) {
            return Err("join did not present the invitation".into());
        }
        let leaf = staged
            .update_path_leaf_node()
            .ok_or("join without a leaf node")?;
        for remove in staged.remove_proposals() {
            let removed = self.group.member_at(remove.remove_proposal().removed());
            if removed.map(|m| m.signature_key) != Some(leaf.signature_key().as_slice().to_vec()) {
                return Err("join tried to remove another member".into());
            }
        }
        let joined = peer(leaf.credential(), leaf.signature_key().as_slice());
        self.group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(err)?;
        Ok(joined)
    }
}

fn carries_invite_psk(staged: &StagedCommit) -> bool {
    // OpenMLS 0.9.2 has no public accessor for a PSK proposal's id, so
    // round-trip through its wire encoding (a proposal is just the id).
    staged.psk_proposals().any(|q| {
        q.psk_proposal()
            .tls_serialize_detached()
            .ok()
            .and_then(|b| PreSharedKeyId::tls_deserialize_exact(b).ok())
            .is_some_and(|id| *id.psk() == invite_psk())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn room() -> (Uuid, [u8; 32], Mls) {
        let room = Uuid::new_v4();
        let psk = [7u8; 32];
        let alice = Mls::create(&Keys::new("alice"), &room, &psk).unwrap();
        (room, psk, alice)
    }

    #[test]
    fn invited_joiner_reads_later_messages_but_not_earlier_ones() {
        let (room, psk, mut alice) = room();
        let earlier = alice.encrypt(b"before").unwrap();
        let info = alice.group_info().unwrap();

        let (mut bob, commit) = Mls::join(&Keys::new("bob"), &room, &psk, &info).unwrap();
        assert_eq!(alice.process_join(&commit).unwrap().name, "bob");
        // Bob holds the invitation, the group info and the earlier ciphertext.
        assert!(bob.process_app(&earlier).is_err());
        let later = alice.encrypt(b"after").unwrap();
        let (from, text) = bob.process_app(&later).unwrap();
        assert_eq!((from.name.as_str(), text.as_slice()), ("alice", &b"after"[..]));
        let reply = bob.encrypt(b"hi").unwrap();
        assert_eq!(alice.process_app(&reply).unwrap().1, b"hi");
    }

    #[test]
    fn joins_that_do_not_prove_the_invitation_are_rejected() {
        let (room, psk, mut alice) = room();
        let info = alice.group_info().unwrap();
        let mallory = Keys::new("mallory");

        // Wrong secret: OpenMLS rejects it (confirmation tag mismatch).
        let (_, commit) = Mls::join(&mallory, &room, &[8u8; 32], &info).unwrap();
        let e = alice.process_join(&commit).unwrap_err();
        assert!(e.contains("ConfirmationTagMismatch"), "{e}");

        // No PSK at all: OpenMLS accepts it, our rule rejects it.
        let (_, commit) = Mls::join_presenting(&mallory, &room, &psk, &info, None).unwrap();
        assert_eq!(
            alice.process_join(&commit).unwrap_err(),
            "join did not present the invitation"
        );

        // A PSK under some other id.
        let other = Psk::External(ExternalPsk::new(b"other".to_vec()));
        let (_, commit) =
            Mls::join_presenting(&mallory, &room, &psk, &info, Some(other)).unwrap();
        assert!(alice.process_join(&commit).is_err());

        // None of that changed the group, and a proper join still works.
        assert_eq!(alice.members().len(), 1);
        let (_, commit) = Mls::join(&Keys::new("bob"), &room, &psk, &info).unwrap();
        assert!(alice.process_join(&commit).is_ok());
    }

    #[test]
    fn group_info_for_another_room_is_refused() {
        let (_, psk, alice) = room();
        let info = alice.group_info().unwrap();
        assert!(Mls::join(&Keys::new("bob"), &Uuid::new_v4(), &psk, &info).is_err());
    }

    #[test]
    fn frames_cannot_cross_between_the_message_and_commit_paths() {
        let (room, psk, mut alice) = room();
        let info = alice.group_info().unwrap();
        let (mut bob, commit) = Mls::join(&Keys::new("bob"), &room, &psk, &info).unwrap();
        // A commit offered as an application frame must not be merged.
        assert!(alice.process_app(&commit).is_err());
        assert_eq!(alice.members().len(), 1);
        assert!(alice.process_join(&commit).is_ok());
        let text = bob.encrypt(b"x").unwrap();
        assert!(alice.process_join(&text).is_err());
        assert!(alice.process_app(&text).is_ok());
    }

    #[test]
    fn rejoin_replaces_only_the_joiners_own_leaf() {
        let (room, psk, mut alice) = room();
        let bob_keys = Keys::new("bob");
        let (bob, commit) =
            Mls::join(&bob_keys, &room, &psk, &alice.group_info().unwrap()).unwrap();
        alice.process_join(&commit).unwrap();

        // Same signing key: the old leaf is replaced, not duplicated.
        let (mut bob2, commit) =
            Mls::join(&bob_keys, &room, &psk, &bob.group_info().unwrap()).unwrap();
        alice.process_join(&commit).unwrap();
        assert_eq!(alice.members().len(), 2);
        let m = alice.encrypt(b"again").unwrap();
        assert!(bob2.process_app(&m).is_ok());

        // A rejoin by Alice's own key would remove Alice's leaf from under
        // her; her client refuses rather than merge an unverified epoch.
        let alice_keys = alice.keys.clone();
        let (_, commit) =
            Mls::join(&alice_keys, &room, &psk, &alice.group_info().unwrap()).unwrap();
        assert_eq!(
            alice.process_join(&commit).unwrap_err(),
            "join tried to remove this member"
        );
    }
}
