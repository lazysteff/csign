# TRON Signing API

This document describes the TRON signing routes exposed by `chain-signer`. For shared request/response conventions, key lifecycle, verify/recover behavior, policy fields, and client mapping, see [API.md](API.md).

For all TRON routes, `csign` validates request shape, typed fields, configured policy caps where applicable, owner authorization, and protobuf signability only. It does not validate live chain state. The TRON node or the caller's orchestrator remains responsible for stateful checks such as account existence, witness existence and eligibility, available TRON Power, current rewards, reward-claim timing restrictions, guard representative restrictions, delegable balance, receiver eligibility, unfreeze-entry limits, expired-unfreeze availability, unstake maturity, and expiration freshness against current chain time.

The `owner_address` routes are forward-only additions. There is no backward compatibility layer, migration, alias route, or support for previously submitted signing requests. Payload recovery is stateless: `recover` and `verify` may classify any structurally valid signed TRON payload for a newly supported contract type, including payloads created outside `csign`.

For verified voting and reward semantics, protobuf `support` handling, and source links, see [TRON Governance And Reward Semantics](TRON_GOVERNANCE_REWARDS.md).

Business policy remains outside `csign`: witness selection, witness allowlists, allocation limits, voting strategy, and reward-claim scheduling belong to the asset-management orchestration layer. `csign` intentionally adds only signing capability plus deterministic request validation.

## `POST v1/tron/transfers/trx/sign`

Request type: `TRXTransferSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `to` | string | yes | Recipient Base58 address. |
| `amount` | int64 | yes | TRX amount. |
| `fee_limit` | int64 | yes | TRON fee limit. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. |
| `ref_block_num` | int64 | no | Reference block number. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. |

Response `operation`: `tron_transfer_trx`

## `POST v1/tron/transfers/trc20/sign`

Request type: `TRC20TransferSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `to` | string | yes | Recipient Base58 address. |
| `token_contract` | string | yes | TRC-20 contract Base58 address. |
| `amount` | string | yes | Token amount. |
| `fee_limit` | int64 | yes | TRON fee limit. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. |
| `ref_block_num` | int64 | no | Reference block number. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. |

Response `operation`: `tron_transfer_trc20`

## `POST v1/tron/resources/freeze_v2/sign`

Request type: `TRONFreezeBalanceV2SignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `owner_address` | string | yes | Owner Base58 address. |
| `resource` | string | yes | `BANDWIDTH` or `ENERGY`. |
| `amount` | int64 | yes | Amount mapped to `frozen_balance`. Must be greater than `0`. |
| `fee_limit` | int64 | no | Copied into `raw_data.fee_limit` when provided. Defaults to `0`. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. Must decode to 2 bytes. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. Must decode to 8 bytes. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. Must be greater than `timestamp`. |

Response `operation`: `tron_freeze_balance_v2`

## `POST v1/tron/resources/unfreeze_v2/sign`

Request type: `TRONUnfreezeBalanceV2SignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `owner_address` | string | yes | Owner Base58 address. |
| `resource` | string | yes | `BANDWIDTH` or `ENERGY`. `TRON_POWER` is intentionally rejected. |
| `amount` | int64 | yes | Amount mapped to `unfreeze_balance`. Must be greater than `0`. |
| `fee_limit` | int64 | no | Copied into `raw_data.fee_limit` when provided. Defaults to `0`. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. Must decode to 2 bytes. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. Must decode to 8 bytes. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. Must be greater than `timestamp`. |

Response `operation`: `tron_unfreeze_balance_v2`

## `POST v1/tron/resources/delegate/sign`

Request type: `TRONDelegateResourceSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `owner_address` | string | yes | Owner Base58 address. |
| `receiver_address` | string | yes | Receiver Base58 address. |
| `resource` | string | yes | `BANDWIDTH` or `ENERGY`. |
| `amount` | int64 | yes | Amount mapped to `balance`. Must be greater than `0`. |
| `lock` | bool | no | Delegation lock flag. Defaults to `false`. |
| `lock_period` | int64 | no | Delegation lock period. Must be greater than `0` only when `lock=true`, otherwise it must be `0`. |
| `fee_limit` | int64 | no | Copied into `raw_data.fee_limit` when provided. Defaults to `0`. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. Must decode to 2 bytes. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. Must decode to 8 bytes. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. Must be greater than `timestamp`. |

Response `operation`: `tron_delegate_resource`

## `POST v1/tron/resources/undelegate/sign`

Request type: `TRONUndelegateResourceSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `owner_address` | string | yes | Owner Base58 address. |
| `receiver_address` | string | yes | Receiver Base58 address. |
| `resource` | string | yes | `BANDWIDTH` or `ENERGY`. |
| `amount` | int64 | yes | Amount mapped to `balance`. Must be greater than `0`. |
| `fee_limit` | int64 | no | Copied into `raw_data.fee_limit` when provided. Defaults to `0`. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. Must decode to 2 bytes. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. Must decode to 8 bytes. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. Must be greater than `timestamp`. |

Response `operation`: `tron_undelegate_resource`

## `POST v1/tron/resources/withdraw_expire_unfreeze/sign`

Request type: `TRONWithdrawExpireUnfreezeSignRequest`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `owner_address` | string | yes | Owner Base58 address. |
| `fee_limit` | int64 | no | Copied into `raw_data.fee_limit` when provided. Defaults to `0`. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. Must decode to 2 bytes. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. Must decode to 8 bytes. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. Must be greater than `timestamp`. |

Response `operation`: `tron_withdraw_expire_unfreeze`

This route is for Stake 2.0 expired unfreeze withdrawal after `UnfreezeBalanceV2Contract`. It is not SR/voter reward claiming and is separate from `v1/tron/rewards/withdraw_balance/sign`.

## `POST v1/tron/governance/vote_witness/sign`

Request type: `TRONVoteWitnessSignRequest`

Purpose: sign `VoteWitnessContract` to replace the owner's SR/SR-partner vote allocation with the submitted list.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `owner_address` | string | yes | Voter Base58 address. |
| `votes` | array | yes | Complete desired vote allocation. Must contain 1 to 30 entries. |
| `votes[].vote_address` | string | yes | Witness or SR-candidate Base58 address. Duplicate normalized addresses are rejected by `csign`. |
| `votes[].vote_count` | int64 | yes | Positive integer number of votes. |
| `fee_limit` | int64 | no | Copied into `raw_data.fee_limit` when provided. Defaults to `0`. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. Must decode to 2 bytes. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. Must decode to 8 bytes. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. Must be greater than `timestamp`. |

Response `operation`: `tron_vote_witness`

`csign` does not enforce witness allowlists, business allocation caps, witness existence, witness eligibility, account existence, available TRON Power, or reward scheduling. It also does not create a follow-up reward-claim action after voting.

## `POST v1/tron/rewards/withdraw_balance/sign`

Request type: `TRONWithdrawBalanceSignRequest`

Purpose: sign `WithdrawBalanceContract` for SR/voter reward claiming and movement of reward allowance into account balance.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `owner_address` | string | yes | SR or voter Base58 address. |
| `fee_limit` | int64 | no | Copied into `raw_data.fee_limit` when provided. Defaults to `0`. |
| `ref_block_bytes` | string | yes | Reference block bytes as hex. Must decode to 2 bytes. |
| `ref_block_hash` | string | yes | Reference block hash bytes as hex. Must decode to 8 bytes. |
| `timestamp` | int64 | yes | Request timestamp in milliseconds. |
| `expiration` | int64 | yes | Expiration timestamp in milliseconds. Must be greater than `timestamp`. |

Response `operation`: `tron_withdraw_balance`

This route is reward claiming only. It is distinct from Stake 2.0 `withdraw_expire_unfreeze`, and it does not represent unstaking or matured unfreeze withdrawal. In the verified `GreatVoyage-v4.8.1.1` runtime, `WithdrawBalanceContract` calculates/settles pending rewards into allowance through `withdrawReward(owner)`, then moves allowance into spendable balance and clears allowance. `csign` does not check current rewards, minimum claim amount, claim timing, or guard representative restrictions.

## API To Protobuf Mapping

| API route | Public field | Protobuf field |
| --- | --- | --- |
| `freeze_v2` | `owner_address` | `owner_address` |
| `freeze_v2` | `amount` | `frozen_balance` |
| `freeze_v2` | `resource` | `resource` |
| `unfreeze_v2` | `owner_address` | `owner_address` |
| `unfreeze_v2` | `amount` | `unfreeze_balance` |
| `unfreeze_v2` | `resource` | `resource` |
| `delegate` | `owner_address` | `owner_address` |
| `delegate` | `receiver_address` | `receiver_address` |
| `delegate` | `amount` | `balance` |
| `delegate` | `lock` | `lock` |
| `delegate` | `lock_period` | `lock_period` |
| `undelegate` | `owner_address` | `owner_address` |
| `undelegate` | `receiver_address` | `receiver_address` |
| `undelegate` | `amount` | `balance` |
| `withdraw_expire_unfreeze` | `owner_address` | `owner_address` |
| `vote_witness` | `owner_address` | `owner_address` |
| `vote_witness` | `votes[].vote_address` | `votes.vote_address` |
| `vote_witness` | `votes[].vote_count` | `votes.vote_count` |
| `vote_witness` | n/a | `support` remains protobuf default; not exposed |
| `withdraw_balance` | `owner_address` | `owner_address` |

## Non-goals And Boundaries

- Legacy Stake 1.0 `FreezeBalanceContract` and `UnfreezeBalanceContract`
- `CancelAllUnfreezeV2`
- signer-side expiration freshness windows
- read/query helpers for delegable or withdrawable balances
- automatic TRON state inspection before signing
- `TRON_POWER` governance-style unfreeze
- witness selection, allowlists, allocation limits, or voting strategy
- reward-claim scheduling or automatic reward-claim follow-up actions
