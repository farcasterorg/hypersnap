import { useEffect, useState } from "react";
import { useAccount, useSwitchChain } from "wagmi";
import type { Chain, Hex } from "viem";
import {
  checkDeployStatus,
  deploy,
  type DeployPhase,
  type DeployStatus,
} from "../deploy";

interface ChainCardProps {
  chain: Chain;
}

export function ChainCard({ chain }: ChainCardProps) {
  const { address, chainId: connectedChainId } = useAccount();
  const { switchChainAsync } = useSwitchChain();
  const [status, setStatus] = useState<DeployStatus>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [phase, setPhase] = useState<DeployPhase | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    if (!address) return;
    setStatus({ kind: "loading" });
    try {
      const next = await checkDeployStatus(address, chain.id);
      setStatus(next);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setStatus({ kind: "no-createx" });
      setError(`status check failed: ${msg}`);
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address, chain.id]);

  async function handleDeploy() {
    if (!address) return;
    setBusy(true);
    setError(null);
    setLog([]);
    setPhase(null);
    try {
      if (connectedChainId !== chain.id) {
        setLog((l) => [...l, `Switching wallet to ${chain.name}…`]);
        await switchChainAsync({
          chainId: chain.id as Parameters<typeof switchChainAsync>[0]["chainId"],
        });
      }
      const result = await deploy(address, chain.id, {
        onLog: (msg) => setLog((l) => [...l, msg]),
        onPhase: (p) => setPhase(p),
      });
      if (result.kind === "already-deployed") {
        setStatus({
          kind: "deployed",
          proxy: result.proxy,
          impl: result.impl,
        });
        setLog((l) => [...l, "Already deployed; nothing to do."]);
      } else {
        setStatus({
          kind: "deployed",
          proxy: result.proxy,
          impl: result.impl,
        });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
    } finally {
      setBusy(false);
    }
  }

  const explorerBase = chain.blockExplorers?.default.url;
  const isConnectedHere = connectedChainId === chain.id;

  return (
    <div className={`chain-card ${chain.testnet ? "testnet" : ""}`}>
      <div className="chain-header">
        <h3>{chain.name}</h3>
        <span className="chain-id">chainId {chain.id}</span>
      </div>

      {status.kind === "loading" && (
        <div className="status loading">checking…</div>
      )}

      {status.kind === "no-createx" && (
        <div className="status error">
          CreateX not deployed on this chain at the canonical address.
        </div>
      )}

      {status.kind === "deployed" && (
        <div className="status deployed">
          <div className="check">✓ Deployed</div>
          <div className="addresses">
            <Address
              label="Proxy"
              addr={status.proxy}
              explorer={explorerBase}
            />
            <Address
              label="Impl"
              addr={status.impl}
              explorer={explorerBase}
            />
          </div>
        </div>
      )}

      {status.kind === "pending" && (
        <div className="status pending">
          <div className="addresses">
            <Address
              label="Proxy (predicted)"
              addr={status.expectedProxy}
              explorer={explorerBase}
            />
            <Address
              label="Impl (predicted)"
              addr={status.expectedImpl}
              explorer={explorerBase}
            />
          </div>
          <button
            className="deploy-btn"
            onClick={handleDeploy}
            disabled={busy}
          >
            {busy
              ? "Deploying…"
              : isConnectedHere
                ? `Deploy on ${chain.name}`
                : `Switch + deploy on ${chain.name}`}
          </button>
        </div>
      )}

      {busy && <DeploySteps phase={phase} explorerBase={explorerBase} />}

      {log.length > 0 && (
        <ul className="log">
          {log.map((m, i) => (
            <li key={i}>{m}</li>
          ))}
        </ul>
      )}

      {error && <div className="status error">{error}</div>}
    </div>
  );
}

interface DeployStepsProps {
  phase: DeployPhase | null;
  explorerBase?: string;
}

function DeploySteps({ phase, explorerBase }: DeployStepsProps) {
  // Derive the per-step state from the most-recent phase event. Once a
  // step is confirmed/skipped we keep showing it as "done" while the
  // next step progresses.
  const implState = stateOf("impl", phase);
  const proxyState = stateOf("proxy", phase);

  const implStep = phaseDetail("impl", phase);
  const proxyStep = phaseDetail("proxy", phase);

  return (
    <div className="deploy-steps">
      <StepRow
        index={1}
        of={2}
        title="Implementation contract"
        state={implState}
        detail={implStep}
        explorerBase={explorerBase}
      />
      <StepRow
        index={2}
        of={2}
        title="Proxy + initialize"
        state={proxyState}
        detail={proxyStep}
        explorerBase={explorerBase}
      />
    </div>
  );
}

type RowState = "idle" | "active" | "done" | "skipped";

function stateOf(step: "impl" | "proxy", phase: DeployPhase | null): RowState {
  if (!phase) return "idle";

  // Once the proxy phase has begun, the impl phase is fully resolved.
  if (step === "impl") {
    if (phase.step === "proxy") return "done";
    if (phase.step === "impl") {
      if (phase.status === "already-exists") return "skipped";
      if (phase.status === "confirmed") return "done";
      return "active";
    }
  }

  if (step === "proxy") {
    if (phase.step === "impl") return "idle";
    if (phase.step === "proxy") {
      if (phase.status === "confirmed") return "done";
      return "active";
    }
  }
  return "idle";
}

interface StepDetail {
  label: string;
  address?: string;
  tx?: Hex;
  emphasis?: boolean;
}

function phaseDetail(
  step: "impl" | "proxy",
  phase: DeployPhase | null,
): StepDetail | null {
  if (!phase || phase.step !== step) return null;
  switch (phase.status) {
    case "checking":
      return { label: "Checking on-chain state…" };
    case "already-exists":
      return {
        label: "Already deployed",
        address: phase.address,
      };
    case "preparing":
      return {
        label: "Building transaction…",
        address: phase.address,
      };
    case "signing":
      return {
        label: "Sign in wallet now",
        address: phase.address,
        emphasis: true,
      };
    case "pending":
      return {
        label: "Waiting for confirmation…",
        address: phase.address,
        tx: phase.tx,
      };
    case "confirmed":
      return {
        label: "Confirmed",
        address: phase.address,
        tx: phase.tx,
      };
  }
}

function StepRow({
  index,
  of,
  title,
  state,
  detail,
  explorerBase,
}: {
  index: number;
  of: number;
  title: string;
  state: RowState;
  detail: StepDetail | null;
  explorerBase?: string;
}) {
  const icon =
    state === "done"
      ? "✓"
      : state === "skipped"
        ? "↷"
        : state === "active"
          ? "●"
          : "○";

  return (
    <div className={`step-row state-${state} ${detail?.emphasis ? "emphasis" : ""}`}>
      <div className="step-icon">{icon}</div>
      <div className="step-body">
        <div className="step-title">
          <span className="step-counter">
            Step {index}/{of}
          </span>
          <span>{title}</span>
        </div>
        {detail && (
          <div className="step-meta">
            <div className="step-label">{detail.label}</div>
            {detail.address && (
              <div className="step-addr">
                {explorerBase ? (
                  <a
                    href={`${explorerBase}/address/${detail.address}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <code>{detail.address}</code>
                  </a>
                ) : (
                  <code>{detail.address}</code>
                )}
              </div>
            )}
            {detail.tx && (
              <div className="step-addr">
                {explorerBase ? (
                  <a
                    href={`${explorerBase}/tx/${detail.tx}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <code>tx: {detail.tx.slice(0, 10)}…{detail.tx.slice(-8)}</code>
                  </a>
                ) : (
                  <code>tx: {detail.tx.slice(0, 10)}…</code>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Address({
  label,
  addr,
  explorer,
}: {
  label: string;
  addr: string;
  explorer?: string;
}) {
  const url = explorer ? `${explorer}/address/${addr}` : undefined;
  return (
    <div className="addr-row">
      <span className="addr-label">{label}:</span>
      {url ? (
        <a href={url} target="_blank" rel="noreferrer">
          <code>{addr}</code>
        </a>
      ) : (
        <code>{addr}</code>
      )}
    </div>
  );
}
