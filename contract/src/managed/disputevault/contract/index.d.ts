import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export enum DisputeStatus { SUBMITTED = 0, VERDICT_POSTED = 1 }

export type Dispute = { evidence_commitment: Uint8Array;
                        envelope: Uint8Array;
                        verdict_commitment: Uint8Array;
                        status: DisputeStatus
                      };

export type Witnesses<PS> = {
  adminSecret(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
}

export type ImpureCircuits<PS> = {
  register_platform(context: __compactRuntime.CircuitContext<PS>,
                    platform_public_key_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  submit_dispute(context: __compactRuntime.CircuitContext<PS>,
                 evidence_wire_0: Uint8Array,
                 envelope_0: Uint8Array): __compactRuntime.CircuitResults<PS, bigint>;
  post_verdict(context: __compactRuntime.CircuitContext<PS>,
               dispute_id_0: bigint,
               verdict_wire_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type ProvableCircuits<PS> = {
  register_platform(context: __compactRuntime.CircuitContext<PS>,
                    platform_public_key_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  submit_dispute(context: __compactRuntime.CircuitContext<PS>,
                 evidence_wire_0: Uint8Array,
                 envelope_0: Uint8Array): __compactRuntime.CircuitResults<PS, bigint>;
  post_verdict(context: __compactRuntime.CircuitContext<PS>,
               dispute_id_0: bigint,
               verdict_wire_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type PureCircuits = {
}

export type Circuits<PS> = {
  register_platform(context: __compactRuntime.CircuitContext<PS>,
                    platform_public_key_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  submit_dispute(context: __compactRuntime.CircuitContext<PS>,
                 evidence_wire_0: Uint8Array,
                 envelope_0: Uint8Array): __compactRuntime.CircuitResults<PS, bigint>;
  post_verdict(context: __compactRuntime.CircuitContext<PS>,
               dispute_id_0: bigint,
               verdict_wire_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type Ledger = {
  readonly admin_authority: Uint8Array;
  readonly platform_enc_key: Uint8Array;
  readonly dispute_counter: bigint;
  disputes: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: bigint): boolean;
    lookup(key_0: bigint): Dispute;
    [Symbol.iterator](): Iterator<[bigint, Dispute]>
  };
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>,
               admin_secret_0: Uint8Array): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
