import React, { useMemo, useState } from "react";
import { useAccount } from "wagmi";
import { isAddress, isHex, type Address, type Hex } from "viem";
import { buildRoot, proofFor, sortHexAscending } from "../lib/merkle";
import { lockLeafEvm } from "../lib/leaf";

export interface LockEntry {
  lockId: string;
  destinationChainId: string;
  recipient: string;
  amount: string;
}

interface RowErrors {
  lockId?: string;
  destinationChainId?: string;
  recipient?: string;
  amount?: string;
}

function validateRow(r: LockEntry): RowErrors {
  const e: RowErrors = {};
  const lid = r.lockId.trim();
  const cidStr = r.destinationChainId.trim();
  const rcpt = r.recipient.trim();
  const amt = r.amount.trim();

  if (!lid) e.lockId = "required";
  else if (!isHex(lid)) e.lockId = "must start with 0x and contain only hex";
  else if (lid.length !== 66)
    e.lockId = `must be 32 bytes (0x + 64 hex chars; got ${lid.length - 2})`;

  if (!cidStr) e.destinationChainId = "required";
  else {
    const cid = Number(cidStr);
    if (!Number.isInteger(cid) || cid <= 0) e.destinationChainId = "positive integer";
    else if (cid > 0xffffffff) e.destinationChainId = "exceeds uint32 max";
  }

  if (!rcpt) e.recipient = "required";
  else if (!isAddress(rcpt, { strict: false })) e.recipient = "not a valid address";

  if (!amt) e.amount = "required";
  else {
    try {
      const a = BigInt(amt);
      if (a <= 0n) e.amount = "must be > 0";
    } catch {
      e.amount = "not a valid integer";
    }
  }
  return e;
}

function rowIsValid(e: RowErrors): boolean {
  return !e.lockId && !e.destinationChainId && !e.recipient && !e.amount;
}

function randomLockId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

export interface BuiltLeaf {
  source: LockEntry;
  parsed: {
    lockId: Hex;
    destinationChainId: number;
    recipient: Address;
    amount: bigint;
  };
  leafHash: Hex;
  proof: Hex[];
}

export interface BuiltTree {
  root: Hex;
  entries: BuiltLeaf[];
}

interface Props {
  onTree: (t: BuiltTree | null) => void;
}

export function MerkleTreeBuilder({ onTree }: Props) {
  const { chainId: connectedChainId, address } = useAccount();
  const [rows, setRows] = useState<LockEntry[]>([
    {
      lockId: "",
      destinationChainId: connectedChainId ? String(connectedChainId) : "",
      recipient: "",
      amount: "",
    },
  ]);
  const [error, setError] = useState<string | null>(null);
  const [tree, setTree] = useState<BuiltTree | null>(null);

  function update(idx: number, field: keyof LockEntry, value: string) {
    setRows((rs) =>
      rs.map((r, i) => (i === idx ? { ...r, [field]: value } : r)),
    );
  }

  function addRow() {
    setRows((rs) => [
      ...rs,
      {
        lockId: "",
        destinationChainId: connectedChainId ? String(connectedChainId) : "",
        recipient: address ?? "",
        amount: "",
      },
    ]);
  }

  function removeRow(idx: number) {
    setRows((rs) => rs.filter((_, i) => i !== idx));
  }

  function genLockId(idx: number) {
    update(idx, "lockId", randomLockId());
  }

  function fillSelf(idx: number) {
    if (address) update(idx, "recipient", address);
  }

  // Per-row validation errors for inline feedback.
  const rowErrors = useMemo(() => rows.map(validateRow), [rows]);
  const valid = rows.length > 0 && rowErrors.every(rowIsValid);

  function build() {
    setError(null);
    setTree(null);
    onTree(null);
    if (!valid) {
      setError("One or more rows have invalid input.");
      return;
    }
    try {
      const lookups = new Set<string>();
      const parsedRows = rows.map((r) => {
        const lockId = r.lockId as Hex;
        const destinationChainId = Number(r.destinationChainId);
        const recipient = r.recipient as Address;
        const amount = BigInt(r.amount);
        const key = `${lockId.toLowerCase()}:${destinationChainId}`;
        if (lookups.has(key)) {
          throw new Error(
            `Duplicate (lockId, destinationChainId) pair: ${r.lockId} on chain ${destinationChainId}`,
          );
        }
        lookups.add(key);
        return {
          source: r,
          parsed: { lockId, destinationChainId, recipient, amount },
          leafHash: lockLeafEvm(lockId, destinationChainId, recipient, amount),
        };
      });

      // Canonical ordering: ascending by leaf hash.
      const sortedHashes = sortHexAscending(parsedRows.map((p) => p.leafHash));
      const sortedRows = sortedHashes.map(
        (h) => parsedRows.find((p) => p.leafHash === h)!,
      );

      const root = buildRoot(sortedHashes);
      const entries: BuiltLeaf[] = sortedRows.map((p, idx) => ({
        ...p,
        proof: proofFor(sortedHashes, idx),
      }));

      const next: BuiltTree = { root, entries };
      setTree(next);
      onTree(next);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
    }
  }

  return (
    <div className="tree-builder">
      <h2>Merkle Tree</h2>
      <p className="hint">
        Add lock entries to build a verifiable tree. Each row represents one
        EVM-family lock; the family byte and chainId are baked into the leaf
        hash and verified on-chain by the destination bridge.
      </p>

      <div className="lock-rows">
        {rows.map((r, i) => {
          const errs = rowErrors[i];
          return (
            <div className="lock-row" key={i}>
              <div className="lock-row-header">
                <span className="row-num">#{i + 1}</span>
                {rows.length > 1 && (
                  <button
                    className="secondary tiny"
                    onClick={() => removeRow(i)}
                    title="Remove row"
                  >
                    ✕
                  </button>
                )}
              </div>

              <FormField
                label="lockId"
                error={errs.lockId}
                hint="32-byte hex (0x + 64 hex chars)"
                tail={
                  <button
                    className="secondary tiny"
                    onClick={() => genLockId(i)}
                    title="Fill with a random 32-byte value"
                  >
                    random
                  </button>
                }
              >
                <input
                  type="text"
                  placeholder="0x…"
                  value={r.lockId}
                  onChange={(e) => update(i, "lockId", e.target.value)}
                  spellCheck={false}
                />
              </FormField>

              <div className="row-grid-2">
                <FormField
                  label="chainId"
                  error={errs.destinationChainId}
                  hint="EVM chain id (decimal)"
                >
                  <input
                    type="text"
                    placeholder="1"
                    value={r.destinationChainId}
                    onChange={(e) =>
                      update(i, "destinationChainId", e.target.value)
                    }
                    spellCheck={false}
                  />
                </FormField>

                <FormField
                  label="amount"
                  error={errs.amount}
                  hint="in SNAP wei (1 SNAP = 10^6 wei since decimals=6)"
                >
                  <input
                    type="text"
                    placeholder="1000000"
                    value={r.amount}
                    onChange={(e) => update(i, "amount", e.target.value)}
                    spellCheck={false}
                  />
                </FormField>
              </div>

              <FormField
                label="recipient"
                error={errs.recipient}
                hint="20-byte EVM address"
                tail={
                  address && (
                    <button
                      className="secondary tiny"
                      onClick={() => fillSelf(i)}
                      title="Fill with the connected wallet address"
                    >
                      use my address
                    </button>
                  )
                }
              >
                <input
                  type="text"
                  placeholder="0x…"
                  value={r.recipient}
                  onChange={(e) => update(i, "recipient", e.target.value)}
                  spellCheck={false}
                />
              </FormField>
            </div>
          );
        })}
      </div>

      <div className="row-actions">
        <button className="secondary" onClick={addRow}>
          + Add row
        </button>
        <button onClick={build} disabled={!valid}>
          {valid ? "Build Tree" : "Fix errors above to enable"}
        </button>
      </div>

      {error && <div className="status error">{error}</div>}

      {tree && (
        <div className="tree-output">
          <div className="addr-row">
            <span className="addr-label">Root:</span>
            <code>{tree.root}</code>
          </div>
          <details>
            <summary>{tree.entries.length} leaves (sorted)</summary>
            <ul className="leaves-list">
              {tree.entries.map((e, i) => (
                <li key={i}>
                  <code>{e.leafHash}</code>
                  <div className="leaf-detail">
                    {e.parsed.recipient} ← {e.parsed.amount.toString()} wei on
                    chainId {e.parsed.destinationChainId}
                  </div>
                </li>
              ))}
            </ul>
          </details>
          <button
            className="secondary"
            onClick={() => copyTreeJson(tree)}
            style={{ marginTop: 8 }}
          >
            Copy tree.json
          </button>
        </div>
      )}
    </div>
  );
}

function copyTreeJson(tree: BuiltTree) {
  const out = {
    root: tree.root,
    leaves: tree.entries.map((e) => ({
      lock_id: e.parsed.lockId,
      destination_chain_id: e.parsed.destinationChainId,
      recipient: e.parsed.recipient,
      amount: e.parsed.amount.toString(),
      leaf_hash: e.leafHash,
      merkle_proof: e.proof,
    })),
  };
  navigator.clipboard.writeText(JSON.stringify(out, null, 2));
}

interface FormFieldProps {
  label: string;
  error?: string;
  hint?: string;
  tail?: React.ReactNode;
  children: React.ReactNode;
}

function FormField({ label, error, hint, tail, children }: FormFieldProps) {
  return (
    <div className={`field ${error ? "field-error" : ""}`}>
      <div className="field-label-row">
        <label>{label}</label>
        {tail}
      </div>
      {children}
      <div className="field-status">
        {error ? (
          <span className="field-error-text">{error}</span>
        ) : (
          hint && <span className="field-hint">{hint}</span>
        )}
      </div>
    </div>
  );
}
