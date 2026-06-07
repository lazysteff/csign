# TRON Governance And Reward Semantics

This note records the verification context for `v1/tron/governance/vote_witness/sign` and `v1/tron/rewards/withdraw_balance/sign`.

## Voting

The current TRON contract documentation describes `VoteWitnessContract.votes` as a maximum-30-item list and says `vote_count` is an integer number of votes, with 1 vote corresponding to 1 staked TRX. The java-tron Super Representative documentation says every new vote completely overwrites previous voting effects.

In `GreatVoyage-v4.8.1.1`, `VoteWitnessActuator` validates `MAX_VOTE_NUMBER = 30`, validates positive vote counts, checks the summed vote count against TRON Power after multiplying by `TRX_PRECISION = 1,000,000`, clears the account's current votes, and then adds the submitted list. Callers must therefore submit the full desired vote allocation, not a delta.

`csign` treats duplicate normalized witness addresses as a deterministic API error so allocations are unambiguous. This is a `csign` rule, not documented here as a separate TRON protocol rule.

## Protobuf Support Field

Current java-tron system-contract documentation still includes the protobuf `VoteWitnessContract.support` field and describes it as constant/not used. The `GreatVoyage-v4.8.1.1` actuator does not read it. `csign` does not expose `support` in the public API and leaves it at the protobuf default value. Contract serialization tests assert that the generated `VoteWitnessContract.Support` remains `false`.

## Rewards

The reward-accounting behavior differs by contract in the verified baseline. TRON's java-tron SR documentation states that voter reward distribution is triggered by `VoteWitnessContract`, `UnfreezeBalanceContract`, `UnfreezeBalanceV2Contract`, and `WithdrawBalanceContract`, while rewards are moved to account balance by `WithdrawBalanceContract`.

In the `GreatVoyage-v4.8.1.1` source checked for this release, `VoteWitnessActuator` has the `mortgageService.withdrawReward(ownerAddress)` call commented out, so vote execution replaces votes and does not settle rewards into allowance in that runtime. `WithdrawBalanceActuator` calls `withdrawReward(owner)` first, then moves the resulting allowance into spendable account balance, clears allowance, and updates the latest withdraw time.

## Runtime Acceptance Gate

No project dependency pins a deployment-specific java-tron node runtime. Before merge or deployment, compare the current TRON HTTP API documentation, protobuf/system-contract documentation, `GreatVoyage-v4.8.1.1`, and the deployment-supported java-tron version. Record any runtime-specific differences before treating the above behavior as final for an environment.

## Sources

- [TRON contract-type documentation](https://developers.tron.network/docs/tron-contracttype)
- [java-tron Super Representative documentation](https://tronprotocol.github.io/documentation-en/mechanism-algorithm/sr/)
- [java-tron system-contract documentation](https://tronprotocol.github.io/documentation-en/mechanism-algorithm/system-contracts/)
- [GreatVoyage-v4.8.1.1 VoteWitnessActuator](https://raw.githubusercontent.com/tronprotocol/java-tron/GreatVoyage-v4.8.1.1/actuator/src/main/java/org/tron/core/actuator/VoteWitnessActuator.java)
- [GreatVoyage-v4.8.1.1 WithdrawBalanceActuator](https://raw.githubusercontent.com/tronprotocol/java-tron/GreatVoyage-v4.8.1.1/actuator/src/main/java/org/tron/core/actuator/WithdrawBalanceActuator.java)
- [GreatVoyage-v4.8.1.1 chain constants](https://raw.githubusercontent.com/tronprotocol/java-tron/GreatVoyage-v4.8.1.1/common/src/main/java/org/tron/core/config/Parameter.java)
