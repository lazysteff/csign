# TRON API

[API index](../API.md)

## TRON sign endpoints

For TRON route schemas, protobuf mappings, live-chain validation boundaries, and governance/reward details, see [TRON_SIGNING.md](../TRON_SIGNING.md).

Supported TRON signing routes:

- `POST v1/tron/transfers/trx/sign`
- `POST v1/tron/transfers/trc20/sign`
- `POST v1/tron/resources/freeze_v2/sign`
- `POST v1/tron/resources/unfreeze_v2/sign`
- `POST v1/tron/resources/delegate/sign`
- `POST v1/tron/resources/undelegate/sign`
- `POST v1/tron/resources/withdraw_expire_unfreeze/sign`
- `POST v1/tron/governance/vote_witness/sign`
- `POST v1/tron/rewards/withdraw_balance/sign`

`csign` validates deterministic request shape, owner authorization, configured policy caps where applicable, and protobuf signability only. It does not validate live chain state. Witness selection, vote allocation strategy, and reward-claim scheduling remain orchestration-layer responsibilities.
