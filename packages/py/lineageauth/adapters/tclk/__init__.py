"""tclk/1 adapter: read, parse, verify, simulate, prepare. Never post, never settle.

`tclk/1` (flop-labs/tclk) lets two agents that met in a Technocore room strike
an HTLC/PTLC deal with signed room messages. LineageAuth answers a different
question about the same frames: *is this agent entitled to post this one?* The
two are kept apart on purpose, and `docs/TCLK_INTEGRATION.md` says how.

    tclk validity      != LineageAuth authority
    LineageAuth authority != settlement validity

Three modes, no fourth:

    READ_ONLY   decode and validate frames; fold a transcript into a state
    SIMULATE    the same, at a stated instant, reporting every rejected step
    PREPARE     the exact bytes, destination and ActionRequest a post would need

This package holds no payment key, mints no secret, implements no rail, and
has no code path that reaches the network. Ported from commit `81a8346`
(v0.1.0) of the reference, against its golden vectors.
"""

from lineageauth.adapters.tclk.authority import (
    NOT_SETTLEMENT_NOTE,
    UNCHECKED_BY_LINEAGEAUTH,
    VERIFICATION_ORDER,
    RequiredAuthority,
    TclkAuthorityDecision,
    counterparty_of,
    required_authority_for,
    verify_tclk_authority,
)
from lineageauth.adapters.tclk.commitments import verify_vote_commitment, vote_commitment
from lineageauth.adapters.tclk.evidence import (
    OUTCOME_PREDICATE,
    draft_frame_artifact,
    draft_outcome_attestation,
    evidence_summary,
    frame_artifact_id,
)
from lineageauth.adapters.tclk.frames import (
    MAX_FRAME_CHARS,
    TCLK_DOMAIN,
    TCLK_PREFIX,
    TCLK_VERSION,
    Frame,
    FrameError,
    accept_core,
    canonical_json,
    contract_id,
    decode_frame,
    encode_frame,
    is_tclk_line,
    offer_id,
    try_decode_frame,
    validate_frame,
    version_of_line,
)
from lineageauth.adapters.tclk.interop import (
    job_reference,
    tclk_status_to_a2a,
    tclk_status_to_acp_phase,
)
from lineageauth.adapters.tclk.locks import (
    SECP256K1_N,
    is_valid_point_statement,
    is_valid_statement,
    validate_deadlines,
    verify_hash_preimage,
    verify_point_witness,
    verify_secret,
)
from lineageauth.adapters.tclk.machine import (
    STATUSES,
    TERMINAL_STATUSES,
    ContractState,
    StepResult,
    apply_frame,
    fold,
    lock_terms,
    open_contract,
)
from lineageauth.adapters.tclk.prepare import (
    MODE_PREPARE,
    MODE_READ_ONLY,
    MODE_SIMULATE,
    MODES,
    PreparedFrame,
    prepare_frame,
    publish,
)
from lineageauth.adapters.tclk.rail import (
    FORBIDDEN_OPERATIONS,
    SettlementRailView,
    refuse_value_movement,
)
from lineageauth.adapters.tclk.venue import (
    KNOWN_RAILS,
    OFFER_ROOM,
    capability_token,
    deal_room,
    parse_capability_token,
    parse_state_note_value,
    room_for_frame,
    state_note,
    state_note_value,
)

__all__ = [
    "FORBIDDEN_OPERATIONS",
    "KNOWN_RAILS",
    "MAX_FRAME_CHARS",
    "MODES",
    "MODE_PREPARE",
    "MODE_READ_ONLY",
    "MODE_SIMULATE",
    "NOT_SETTLEMENT_NOTE",
    "OFFER_ROOM",
    "OUTCOME_PREDICATE",
    "SECP256K1_N",
    "STATUSES",
    "TCLK_DOMAIN",
    "TCLK_PREFIX",
    "TCLK_VERSION",
    "TERMINAL_STATUSES",
    "UNCHECKED_BY_LINEAGEAUTH",
    "VERIFICATION_ORDER",
    "ContractState",
    "Frame",
    "FrameError",
    "PreparedFrame",
    "RequiredAuthority",
    "SettlementRailView",
    "StepResult",
    "TclkAuthorityDecision",
    "accept_core",
    "apply_frame",
    "canonical_json",
    "capability_token",
    "contract_id",
    "counterparty_of",
    "deal_room",
    "decode_frame",
    "draft_frame_artifact",
    "draft_outcome_attestation",
    "encode_frame",
    "evidence_summary",
    "fold",
    "frame_artifact_id",
    "is_tclk_line",
    "is_valid_point_statement",
    "is_valid_statement",
    "job_reference",
    "lock_terms",
    "offer_id",
    "open_contract",
    "parse_capability_token",
    "parse_state_note_value",
    "prepare_frame",
    "publish",
    "refuse_value_movement",
    "required_authority_for",
    "room_for_frame",
    "state_note",
    "state_note_value",
    "tclk_status_to_a2a",
    "tclk_status_to_acp_phase",
    "try_decode_frame",
    "validate_deadlines",
    "validate_frame",
    "verify_hash_preimage",
    "verify_point_witness",
    "verify_secret",
    "verify_tclk_authority",
    "verify_vote_commitment",
    "version_of_line",
    "vote_commitment",
]
