use super::*;

fn extract_orchard_anchor_from_raw_tx(raw_tx_bytes: &[u8]) -> Option<[u8; 32]> {
    let tx = read_pirate_transaction(raw_tx_bytes).ok()?;
    tx.ironwood_bundle()
        .map(|bundle| bundle.anchor().to_bytes())
}

fn extract_sapling_anchor_from_raw_tx(raw_tx_bytes: &[u8]) -> Option<[u8; 32]> {
    let tx = read_pirate_transaction(raw_tx_bytes).ok()?;
    let bundle = tx.sapling_bundle()?;
    bundle
        .shielded_spends()
        .first()
        .map(|spend| spend.anchor().to_bytes())
}

fn parse_sapling_root_from_tree_state(
    tree_state: &pirate_sync_lightd::client::TreeState,
) -> Option<[u8; 32]> {
    let encoded = if !tree_state.sapling_frontier.is_empty() {
        tree_state.sapling_frontier.trim()
    } else if !tree_state.sapling_tree.is_empty() {
        tree_state.sapling_tree.trim()
    } else {
        return None;
    };
    if encoded.is_empty() {
        return None;
    }
    if encoded.len() == 64 {
        return hex::decode(encoded)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    }
    let bytes = hex::decode(encoded).ok()?;
    if let Ok(tree) =
        read_commitment_tree::<sapling::Node, _, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>(
            &bytes[..],
        )
    {
        return Some(tree.root().to_bytes());
    }
    let frontier = read_frontier_v1::<sapling::Node, _>(&bytes[..])
        .or_else(|_| read_frontier_v0::<sapling::Node, _>(&bytes[..]))
        .ok()?;
    Some(frontier.root().to_bytes())
}

fn parse_orchard_root_from_tree_state(
    tree_state: &pirate_sync_lightd::client::TreeState,
) -> Option<[u8; 32]> {
    let encoded = tree_state.ironwood_tree.trim();
    if encoded.is_empty() {
        return None;
    }
    if encoded.len() == 64 {
        return hex::decode(encoded)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    }

    let bytes = hex::decode(encoded).ok()?;
    if let Ok(tree) = read_commitment_tree::<
        orchard::tree::MerkleHashOrchard,
        _,
        { sapling::NOTE_COMMITMENT_TREE_DEPTH },
    >(&bytes[..])
    {
        return Some(tree.root().to_bytes());
    }

    let frontier = read_frontier_v1::<orchard::tree::MerkleHashOrchard, _>(&bytes[..])
        .or_else(|_| read_frontier_v0::<orchard::tree::MerkleHashOrchard, _>(&bytes[..]))
        .ok()?;
    Some(frontier.root().to_bytes())
}

fn encode_hex_opt(bytes: Option<[u8; 32]>) -> String {
    bytes.map(hex::encode).unwrap_or_else(|| "none".to_string())
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SpendSelectionAnchors {
    pub(super) target_height: u64,
    pub(super) conservative_anchor_height: u64,
    pub(super) sapling_anchor_height: u64,
    pub(super) ironwood_anchor_height: u64,
}

fn compute_spend_selection_anchors(
    db: &Database,
    account_id: i64,
) -> Result<SpendSelectionAnchors> {
    let spendability_storage = SpendabilityStateStorage::new(db);
    let anchors = spendability_storage
        .get_target_and_anchor_heights_by_pool_for_account(
            SPENDABILITY_MIN_CONFIRMATIONS,
            account_id,
        )?
        .ok_or_else(|| anyhow!("Anchor height unavailable for spend selection"))?;
    Ok(SpendSelectionAnchors {
        target_height: anchors.target_height,
        conservative_anchor_height: anchors.conservative_anchor_height.max(1),
        sapling_anchor_height: anchors.sapling_anchor_height.max(1),
        ironwood_anchor_height: anchors.ironwood_anchor_height.max(1),
    })
}

fn load_selectable_notes_for_send(
    repo: &Repository,
    account_id: i64,
    anchors: SpendSelectionAnchors,
    key_ids_filter: Option<Vec<i64>>,
    address_ids_filter: Option<Vec<i64>>,
) -> Result<Vec<pirate_core::selection::SelectableNote>> {
    if anchors.sapling_anchor_height == anchors.ironwood_anchor_height {
        return Ok(repo.get_unspent_selectable_notes_at_anchor_filtered(
            account_id,
            anchors.conservative_anchor_height,
            SPENDABILITY_MIN_CONFIRMATIONS,
            key_ids_filter,
            address_ids_filter,
        )?);
    }

    let mut combined = Vec::new();
    let mut seen: HashSet<(Vec<u8>, u32, u8)> = HashSet::new();
    for note in repo.get_unspent_selectable_notes_at_anchor_filtered(
        account_id,
        anchors.sapling_anchor_height,
        SPENDABILITY_MIN_CONFIRMATIONS,
        key_ids_filter.clone(),
        address_ids_filter.clone(),
    )? {
        if note.note_type != pirate_core::selection::NoteType::Sapling {
            continue;
        }
        let key = (note.txid.clone(), note.output_index, 0u8);
        if seen.insert(key) {
            combined.push(note);
        }
    }
    for note in repo.get_unspent_selectable_notes_at_anchor_filtered(
        account_id,
        anchors.ironwood_anchor_height,
        SPENDABILITY_MIN_CONFIRMATIONS,
        key_ids_filter,
        address_ids_filter,
    )? {
        if note.note_type != pirate_core::selection::NoteType::Ironwood {
            continue;
        }
        let key = (note.txid.clone(), note.output_index, 1u8);
        if seen.insert(key) {
            combined.push(note);
        }
    }

    Ok(combined)
}

pub(super) fn normalize_filter_ids(ids: Option<Vec<i64>>) -> Option<Vec<i64>> {
    let values = ids?;
    let mut unique = HashSet::new();
    let mut normalized = Vec::new();
    for id in values {
        if unique.insert(id) {
            normalized.push(id);
        }
    }
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn validate_spendable_key(repo: &Repository, account_id: i64, key_id: i64) -> Result<()> {
    let key = repo
        .get_account_key_by_id(key_id)?
        .ok_or_else(|| anyhow!("Key group not found"))?;
    if key.account_id != account_id {
        return Err(anyhow!("Key group does not belong to this wallet"));
    }
    if !key.spendable {
        return Err(anyhow!("Key group is not spendable"));
    }
    Ok(())
}

pub(super) fn resolve_spend_key_id(
    repo: &Repository,
    account_id: i64,
    key_ids_filter: Option<&[i64]>,
    address_ids_filter: Option<&[i64]>,
) -> Result<Option<i64>> {
    let mut selected_key_id: Option<i64> = None;

    if let Some(ids) = key_ids_filter {
        if !ids.is_empty() {
            let unique: HashSet<i64> = ids.iter().copied().collect();
            if unique.len() > 1 {
                for key_id in unique {
                    validate_spendable_key(repo, account_id, key_id)?;
                }
                selected_key_id = None;
            } else {
                let key_id = *unique.iter().next().unwrap();
                validate_spendable_key(repo, account_id, key_id)?;
                selected_key_id = Some(key_id);
            }
        }
    }

    if let Some(address_ids) = address_ids_filter {
        if !address_ids.is_empty() {
            let addresses = repo.get_all_addresses(account_id)?;
            let mut address_key_ids = HashSet::new();
            for address_id in address_ids {
                let addr = addresses
                    .iter()
                    .find(|addr| addr.id == Some(*address_id))
                    .ok_or_else(|| anyhow!("Address {} not found", address_id))?;
                let key_id = addr
                    .key_id
                    .ok_or_else(|| anyhow!("Address {} is missing key id", address_id))?;
                address_key_ids.insert(key_id);
            }
            if address_key_ids.len() > 1 {
                for key_id in &address_key_ids {
                    validate_spendable_key(repo, account_id, *key_id)?;
                }

                if let Some(existing) = selected_key_id {
                    if !address_key_ids.contains(&existing) {
                        return Err(anyhow!(
                            "Selected key group does not match selected addresses"
                        ));
                    }
                }
                selected_key_id = None;
            } else if let Some(address_key_id) = address_key_ids.iter().next().copied() {
                validate_spendable_key(repo, account_id, address_key_id)?;
                if let Some(existing) = selected_key_id {
                    if existing != address_key_id {
                        return Err(anyhow!(
                            "Selected key group does not match selected addresses"
                        ));
                    }
                } else {
                    selected_key_id = Some(address_key_id);
                }
            }
        }
    }

    Ok(selected_key_id)
}

pub(super) fn auto_select_spend_key_id_for_amount(
    repo: &Repository,
    account_id: i64,
    required_total: u64,
    anchors: SpendSelectionAnchors,
) -> Result<Option<i64>> {
    let account_keys = repo.get_account_keys(account_id)?;
    let selectable_notes = load_selectable_notes_for_send(repo, account_id, anchors, None, None)?;
    Ok(choose_auto_spend_key_id_for_amount(
        &account_keys,
        &selectable_notes,
        required_total,
    ))
}

fn account_key_can_spend_note(
    key: &AccountKey,
    note: &pirate_core::selection::SelectableNote,
) -> bool {
    if !key.spendable {
        return false;
    }

    match note.note_type {
        pirate_core::selection::NoteType::Sapling => key.sapling_extsk.is_some(),
        pirate_core::selection::NoteType::Ironwood => key.orchard_extsk.is_some(),
    }
}

pub(super) fn choose_auto_spend_key_id_for_amount(
    account_keys: &[AccountKey],
    selectable_notes: &[pirate_core::selection::SelectableNote],
    required_total: u64,
) -> Option<i64> {
    let spendable_keys = account_keys
        .iter()
        .filter_map(|key| key.id.map(|key_id| (key_id, key)))
        .collect::<HashMap<_, _>>();
    let mut totals_by_key = HashMap::<i64, u64>::new();

    for note in selectable_notes {
        let Some(key_id) = note.key_id else {
            continue;
        };
        let Some(key) = spendable_keys.get(&key_id) else {
            continue;
        };
        if !account_key_can_spend_note(key, note) {
            continue;
        }
        let total = totals_by_key.entry(key_id).or_insert(0);
        *total = total.saturating_add(note.value);
    }

    let mut qualifying = totals_by_key
        .into_iter()
        .filter(|(_, total)| *total >= required_total)
        .collect::<Vec<_>>();
    qualifying.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    qualifying.first().map(|(key_id, _)| *key_id)
}

pub(super) fn note_balances_by_key_id(
    notes: &[pirate_core::selection::SelectableNote],
) -> HashMap<i64, u64> {
    let mut balances = HashMap::<i64, u64>::new();
    for note in notes {
        let Some(key_id) = note.key_id else {
            continue;
        };
        let entry = balances.entry(key_id).or_insert(0);
        *entry = entry.saturating_add(note.value);
    }
    balances
}

pub(super) fn infer_contributing_key_ids_for_amount(
    notes: &[pirate_core::selection::SelectableNote],
    required_total: u64,
) -> HashSet<i64> {
    let mut note_refs = notes.iter().collect::<Vec<_>>();
    note_refs.sort_by(|a, b| a.value.cmp(&b.value).then_with(|| a.height.cmp(&b.height)));

    let mut total = 0u64;
    let mut contributing = HashSet::<i64>::new();
    for note in note_refs {
        if total >= required_total {
            break;
        }
        total = total.saturating_add(note.value);
        if let Some(key_id) = note.key_id {
            contributing.insert(key_id);
        }
    }

    contributing
}

pub(super) fn choose_multi_key_change_sink_key_id(
    account_keys_by_id: &HashMap<i64, AccountKey>,
    contributing_key_ids: &HashSet<i64>,
    balances_by_key: &HashMap<i64, u64>,
) -> Option<i64> {
    let mut seed_candidates = account_keys_by_id
        .iter()
        .filter_map(|(key_id, key)| {
            if key.spendable
                && key.key_type == KeyType::Seed
                && key.key_scope == KeyScope::Account
                && key.sapling_extsk.is_some()
            {
                Some(*key_id)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    seed_candidates.sort_unstable();
    if let Some(seed_key_id) = seed_candidates.into_iter().next() {
        return Some(seed_key_id);
    }

    let mut ranked_candidates = contributing_key_ids
        .iter()
        .filter_map(|key_id| {
            let key = account_keys_by_id.get(key_id)?;
            if !key.spendable || key.sapling_extsk.is_none() {
                return None;
            }
            Some((*key_id, *balances_by_key.get(key_id).unwrap_or(&0)))
        })
        .collect::<Vec<_>>();
    ranked_candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked_candidates.first().map(|(key_id, _)| *key_id)
}

fn resolve_change_diversifier_index(
    repo: &Repository,
    account_id: i64,
    key_id: i64,
) -> Result<u32> {
    let existing_index = repo
        .get_addresses_by_key(account_id, key_id)?
        .into_iter()
        .filter(|addr| addr.address_scope == pirate_storage_sqlite::AddressScope::Internal)
        .map(|addr| addr.diversifier_index)
        .min();

    Ok(existing_index.unwrap_or(0))
}

const PENDING_SIGN_CONTEXT_TTL_MS: u64 = 10 * 60 * 1000;
const PENDING_SIGN_CONTEXT_MAX_ENTRIES: usize = 128;
const BUILD_AND_SIGN_TIMEOUT_BASE_SECS: u64 = 5 * 60;
const BUILD_AND_SIGN_TIMEOUT_PER_INPUT_SECS: u64 = 15;
const BUILD_AND_SIGN_TIMEOUT_MAX_SECS: u64 = 30 * 60;

#[derive(Debug)]
struct PendingSignContext {
    wallet_id: WalletId,
    required_total: u64,
    created_at_ms: u64,
    key_ids_filter: Option<Vec<i64>>,
    address_ids_filter: Option<Vec<i64>>,
    selected_notes: Vec<pirate_core::selection::SelectableNote>,
}

lazy_static::lazy_static! {
    static ref PENDING_SIGN_CONTEXTS: RwLock<HashMap<String, PendingSignContext>> =
        RwLock::new(HashMap::new());
}

fn normalize_pending_sign_filter_ids(ids: Option<&Vec<i64>>) -> Option<Vec<i64>> {
    ids.map(|values| {
        let mut normalized = values.clone();
        normalized.sort_unstable();
        normalized.dedup();
        normalized
    })
}

fn store_pending_sign_context(pending_id: &str, context: PendingSignContext) {
    let now = unix_timestamp_millis();
    let mut cache = PENDING_SIGN_CONTEXTS.write();
    cache.retain(|_, existing| {
        now.saturating_sub(existing.created_at_ms) <= PENDING_SIGN_CONTEXT_TTL_MS
    });
    cache.insert(pending_id.to_string(), context);
    while cache.len() > PENDING_SIGN_CONTEXT_MAX_ENTRIES {
        let Some(oldest_key) = cache
            .iter()
            .min_by_key(|(_, ctx)| ctx.created_at_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        cache.remove(&oldest_key);
    }
}

fn take_pending_sign_context(
    pending_id: &str,
    wallet_id: &WalletId,
    required_total: u64,
    key_ids_filter: Option<&Vec<i64>>,
    address_ids_filter: Option<&Vec<i64>>,
) -> Option<PendingSignContext> {
    let now = unix_timestamp_millis();
    let expected_key_ids = normalize_pending_sign_filter_ids(key_ids_filter);
    let expected_address_ids = normalize_pending_sign_filter_ids(address_ids_filter);
    let mut cache = PENDING_SIGN_CONTEXTS.write();
    cache.retain(|_, existing| {
        now.saturating_sub(existing.created_at_ms) <= PENDING_SIGN_CONTEXT_TTL_MS
    });
    let ctx = cache.remove(pending_id)?;
    if now.saturating_sub(ctx.created_at_ms) > PENDING_SIGN_CONTEXT_TTL_MS {
        return None;
    }
    if &ctx.wallet_id != wallet_id {
        return None;
    }
    if ctx.required_total != required_total {
        return None;
    }
    if ctx.key_ids_filter != expected_key_ids {
        return None;
    }
    if ctx.address_ids_filter != expected_address_ids {
        return None;
    }
    Some(ctx)
}

fn clear_pending_sign_context(pending_id: &str) {
    PENDING_SIGN_CONTEXTS.write().remove(pending_id);
}

fn build_and_sign_timeout(num_inputs: u32) -> std::time::Duration {
    let input_count = u64::from(num_inputs.max(1));
    let timeout_secs = BUILD_AND_SIGN_TIMEOUT_BASE_SECS
        .saturating_add(input_count.saturating_mul(BUILD_AND_SIGN_TIMEOUT_PER_INPUT_SECS))
        .min(BUILD_AND_SIGN_TIMEOUT_MAX_SECS);
    std::time::Duration::from_secs(timeout_secs)
}

#[derive(Debug)]
struct BroadcastContext {
    wallet_id: WalletId,
    account_id: i64,
    spent_nullifiers: Vec<Vec<u8>>,
    change_amount: u64,
    created_at_ms: u64,
}

#[derive(Debug, Clone)]
struct PendingChangeEntry {
    txid: String,
    change_amount: u64,
    broadcast_at_ms: u64,
}

const PENDING_CHANGE_TTL_MS: u64 = 30 * 60 * 1000;

lazy_static::lazy_static! {
    static ref PENDING_CHANGES: RwLock<HashMap<WalletId, Vec<PendingChangeEntry>>> =
        RwLock::new(HashMap::new());
}

fn normalize_txid_hex(txid: &str) -> Option<String> {
    let normalized = txid.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(normalized)
    } else {
        None
    }
}

pub(super) fn txid_hex_variants_from_bytes(txid_bytes: &[u8]) -> Vec<String> {
    if txid_bytes.is_empty() {
        return Vec::new();
    }
    let direct = hex::encode(txid_bytes);
    if txid_bytes.len() != 32 {
        return vec![direct];
    }
    let mut reversed = txid_bytes.to_vec();
    reversed.reverse();
    let reversed_hex = hex::encode(reversed);
    if reversed_hex == direct {
        vec![direct]
    } else {
        vec![direct, reversed_hex]
    }
}

pub(super) fn add_pending_change(wallet_id: &WalletId, txid: &str, change_amount: u64) {
    if change_amount == 0 {
        return;
    }
    let Some(txid) = normalize_txid_hex(txid) else {
        return;
    };
    let now = unix_timestamp_millis();
    let mut cache = PENDING_CHANGES.write();
    let entries = cache.entry(wallet_id.clone()).or_default();
    entries.retain(|e| now.saturating_sub(e.broadcast_at_ms) <= PENDING_CHANGE_TTL_MS);
    if let Some(existing) = entries.iter_mut().find(|e| e.txid == txid) {
        existing.change_amount = change_amount;
        existing.broadcast_at_ms = now;
        return;
    }
    entries.push(PendingChangeEntry {
        txid,
        change_amount,
        broadcast_at_ms: now,
    });
}

#[cfg(test)]
pub(super) fn clear_pending_changes(wallet_id: &WalletId) {
    PENDING_CHANGES.write().remove(wallet_id);
}

#[cfg(test)]
pub(super) fn has_pending_changes(wallet_id: &WalletId) -> bool {
    PENDING_CHANGES.read().contains_key(wallet_id)
}

pub(super) fn resolve_pending_change(wallet_id: &WalletId, known_txids: &HashSet<String>) -> u64 {
    let now = unix_timestamp_millis();
    let mut cache = PENDING_CHANGES.write();
    let Some(entries) = cache.get_mut(wallet_id) else {
        return 0;
    };
    entries.retain(|e| {
        now.saturating_sub(e.broadcast_at_ms) <= PENDING_CHANGE_TTL_MS
            && !known_txids.contains(&e.txid)
    });
    let total: u64 = entries.iter().map(|e| e.change_amount).sum();
    if entries.is_empty() {
        cache.remove(wallet_id);
    }
    total
}

const BROADCAST_CONTEXT_TTL_MS: u64 = 30 * 60 * 1000;
const BROADCAST_CONTEXT_MAX_ENTRIES: usize = 64;

lazy_static::lazy_static! {
    static ref BROADCAST_CONTEXTS: RwLock<HashMap<String, BroadcastContext>> =
        RwLock::new(HashMap::new());
}

fn store_broadcast_context(txid: &str, context: BroadcastContext) {
    let now = unix_timestamp_millis();
    let mut cache = BROADCAST_CONTEXTS.write();
    cache.retain(|_, existing| {
        now.saturating_sub(existing.created_at_ms) <= BROADCAST_CONTEXT_TTL_MS
    });
    cache.insert(txid.to_string(), context);
    while cache.len() > BROADCAST_CONTEXT_MAX_ENTRIES {
        let Some(oldest_key) = cache
            .iter()
            .min_by_key(|(_, ctx)| ctx.created_at_ms)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        cache.remove(&oldest_key);
    }
}

fn take_broadcast_context(txid: &str) -> Option<BroadcastContext> {
    BROADCAST_CONTEXTS.write().remove(txid)
}
