/**
 * Provenance and node monitor (spec 21–23).
 *
 * The demonstration this view exists for (spec 36 step 7): three nodes agree,
 * one does not. The subtlety worth making visible is that the divergent node
 * passes its *own* integrity check — it was rewritten competently, with every
 * Merkle root and block hash recomputed, so its chain is internally
 * consistent. Local verification is necessary and not sufficient; only
 * cross-node comparison finds it.
 *
 * The coverage bar is the other thing worth seeing: the chain is sealed over a
 * prefix of the timeline, and the records after the cut-off have no commitment
 * at all. Those are the records the forensic engines carry unaided, and the
 * ablation in the evaluation console measures exactly that.
 */

import { useState } from "react";

import { useApp } from "../App";
import {
  Badge,
  ErrorState,
  KeyValue,
  Metric,
  Panel,
  SectionLabel,
  Spinner,
} from "../components/primitives";
import { api } from "../lib/api";
import { dateOnly, num, pct, shortHash, ts } from "../lib/format";
import { useAsync } from "../lib/useAsync";
import type { Block, NodeView } from "../lib/types";

export function NodeMonitor() {
  const { select } = useApp();
  const nodes = useAsync(() => api.nodes(), []);
  const chain = useAsync(() => api.blockchain(60, 0), []);
  const [openBlock, setOpenBlock] = useState<string | null>(null);

  if (nodes.error) return <ErrorState error={nodes.error} onRetry={nodes.reload} />;

  const data = nodes.data;
  const chainData = chain.data;
  const divergent = new Set(data?.divergent ?? []);
  const affectedBlocks = new Set(data?.affected_blocks ?? []);
  const affectedRecords = data?.affected_records ?? [];

  return (
    <div className="h-full min-h-0 overflow-y-auto p-3 space-y-3">
      {/* ---------------------------------------------- chain header */}
      <div className="panel">
        <div className="grid grid-cols-2 md:grid-cols-5 divide-x divide-hairline">
          <Metric
            label="Blocks sealed"
            value={chainData ? num(chainData.height) : "—"}
            sub={chainData?.digest ? `digest ${chainData.digest}` : undefined}
            emphasis
          />
          <Metric
            label="Records committed"
            value={chainData ? num(chainData.committed_records ?? 0) : "—"}
            sub={
              chainData?.sealed_fraction
                ? `${pct(chainData.sealed_fraction, 0)} of timeline`
                : undefined
            }
            accent="#7c8cff"
            emphasis
          />
          <Metric
            label="Chain integrity"
            value={chainData?.valid === undefined ? "—" : chainData.valid ? "VALID" : "BROKEN"}
            sub="majority chain"
            accent={chainData?.valid === false ? "#e5484d" : "#2fa36b"}
            emphasis
          />
          <Metric
            label="Nodes agreeing"
            value={data ? `${data.agreeing?.length ?? 0}/${data.nodes.length}` : "—"}
            sub={
              data?.agreement_fraction !== undefined
                ? `${pct(data.agreement_fraction, 0)} agreement`
                : undefined
            }
            accent={divergent.size > 0 ? "#e5484d" : "#2fa36b"}
            emphasis
          />
          <Metric
            label="Divergent commitments"
            value={num(affectedRecords.length)}
            sub={`${affectedBlocks.size} block(s)`}
            accent={affectedRecords.length > 0 ? "#e5484d" : "#5f6b7d"}
            emphasis
          />
        </div>

        {chainData?.covered_from && chainData.covered_to && (
          <div className="px-3.5 pb-3 pt-1">
            <div className="flex items-baseline justify-between text-2xs text-ink-500">
              <span className="uppercase tracking-[0.1em]">Sealed coverage</span>
              <span className="font-mono">
                {dateOnly(chainData.covered_from)} → {dateOnly(chainData.covered_to)}
              </span>
            </div>
            <div className="mt-1.5 flex h-[5px] rounded-full overflow-hidden bg-obsidian-800">
              <div
                className="bg-signal-indigo"
                style={{ width: `${(chainData.sealed_fraction ?? 0) * 100}%` }}
                title="Committed: hashes sealed into blocks"
              />
              <div
                className="bg-anomaly-low/50"
                style={{ width: `${(1 - (chainData.sealed_fraction ?? 0)) * 100}%` }}
                title="Uncommitted tail: no chain evidence available"
              />
            </div>
            <div className="mt-1.5 flex flex-wrap gap-x-5 text-2xs text-ink-500">
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-signal-indigo" />
                committed — a hash mismatch here is near-proof
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-anomaly-low/60" />
                uncommitted tail — forensic engines carry these alone
              </span>
            </div>
          </div>
        )}
      </div>

      {/* ---------------------------------------------- node topology */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr] gap-3">
        <Panel title="Node consistency">
          {nodes.loading ? (
            <Spinner />
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {(data?.nodes ?? []).map((node) => (
                  <NodeCard key={node.node_id} node={node} />
                ))}
              </div>

              {data?.local_verification && (
                <div className="rounded-xs border border-hairline bg-obsidian-850 p-2.5">
                  <SectionLabel>Local integrity check, per node</SectionLabel>
                  <ul className="space-y-1">
                    {Object.entries(data.local_verification).map(([nodeId, problems]) => (
                      <li key={nodeId} className="flex items-center gap-2 text-2xs">
                        <span className="font-mono text-ink-300 w-5">{nodeId}</span>
                        {problems.length === 0 ? (
                          <span className="text-verified">
                            internally self-consistent
                          </span>
                        ) : (
                          <span className="text-anomaly-critical">
                            {problems.join("; ")}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                  {divergent.size > 0 && (
                    <p className="mt-2 text-2xs text-ink-700 leading-relaxed">
                      Note that node {[...divergent].join(", ")} passes this check. Its
                      chain was rewritten with every root recomputed, so it is valid on
                      its own terms. Only comparing state roots across the network
                      reveals it — which is why node consistency is a separate layer and
                      not a property of any single chain.
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </Panel>

        <Panel title="Divergence localisation">
          {affectedRecords.length === 0 ? (
            <div className="text-2xs text-ink-700">
              Every node agrees on the majority state root. No divergence to localise.
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-2xs text-ink-500 leading-relaxed">
                Comparing state roots says <em>that</em> a node disagrees. Walking the
                two chains block by block says <em>where</em>; comparing the record
                hashes inside the first differing block says <em>which records</em>.
              </p>
              <div>
                <SectionLabel>Affected blocks</SectionLabel>
                <div className="flex flex-wrap gap-1">
                  {[...affectedBlocks].map((blockId) => (
                    <button
                      key={blockId}
                      type="button"
                      className={`btn font-mono ${openBlock === blockId ? "btn-active" : ""}`}
                      onClick={() => setOpenBlock(openBlock === blockId ? null : blockId)}
                    >
                      {blockId}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <SectionLabel>
                  Record commitments that differ — {affectedRecords.length}
                </SectionLabel>
                <div className="flex flex-wrap gap-1.5">
                  {affectedRecords.map((recordId) => (
                    <button
                      key={recordId}
                      type="button"
                      className="font-mono text-2xs text-signal hover:underline"
                      onClick={() => select(recordId, null, "investigate")}
                    >
                      {recordId}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Panel>
      </div>

      {/* ---------------------------------------------- block ledger */}
      <Panel
        title={`Provenance chain — ${num(chainData?.height ?? 0)} blocks`}
        dense
      >
        {chain.loading ? (
          <div className="p-3">
            <Spinner />
          </div>
        ) : (
          <div className="max-h-[420px] overflow-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Block</th>
                  <th className="text-right">#</th>
                  <th>Sealed at</th>
                  <th className="text-right">Records</th>
                  <th>Manifest root</th>
                  <th>State root</th>
                  <th>Previous</th>
                  <th>Signatures</th>
                </tr>
              </thead>
              <tbody>
                {(chainData?.blocks ?? []).map((block) => (
                  <BlockRow
                    key={block.header.block_id}
                    block={block}
                    affected={affectedBlocks.has(block.header.block_id)}
                    open={openBlock === block.header.block_id}
                    onToggle={() =>
                      setOpenBlock(
                        openBlock === block.header.block_id ? null : block.header.block_id,
                      )
                    }
                    onSelectRecord={(id) => select(id, null, "investigate")}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function NodeCard({ node }: { node: NodeView }) {
  const healthy = node.status === "HEALTHY";
  const colour = healthy ? "#2fa36b" : "#e5484d";
  return (
    <div
      className="rounded-xs border px-2.5 py-2.5"
      style={{ borderColor: `${colour}44`, background: `${colour}0d` }}
    >
      <div className="flex items-baseline justify-between">
        <span className="font-mono text-xl" style={{ color: colour }}>
          {node.node_id}
        </span>
        <Badge colour={colour}>{healthy ? "OK" : "DIVERGENT"}</Badge>
      </div>
      <div className="mt-2">
        <KeyValue
          columns={1}
          rows={[
            ["height", String(node.height)],
            ["root", shortHash(node.state_root, 12)],
            ["peers", node.peers.join(", ") || "—"],
            ["endpoint", node.endpoint || "—"],
          ]}
        />
      </div>
      {node.divergent_records.length > 0 && (
        <div className="mt-2 pt-2 border-t border-hairline-faint text-2xs text-anomaly-critical">
          {node.divergent_records.length} rewritten commitment(s) across{" "}
          {node.divergent_blocks.length} block(s)
        </div>
      )}
    </div>
  );
}

function BlockRow({
  block,
  affected,
  open,
  onToggle,
  onSelectRecord,
}: {
  block: Block;
  affected: boolean;
  open: boolean;
  onToggle: () => void;
  onSelectRecord: (id: string) => void;
}) {
  const header = block.header;
  return (
    <>
      <tr onClick={onToggle} data-selected={open}>
        <td className="font-mono text-xs">
          <span className={affected ? "text-anomaly-critical" : "text-signal"}>
            {header.block_id}
          </span>
          {affected && (
            <span className="ml-1.5 text-2xs text-anomaly-critical" title="A node rewrote this block">
              ⚠
            </span>
          )}
        </td>
        <td className="font-mono tnum text-2xs text-ink-500 text-right">{header.index}</td>
        <td className="font-mono text-2xs text-ink-500">{ts(header.timestamp)}</td>
        <td className="font-mono tnum text-2xs text-ink-300 text-right">
          {header.record_count}
        </td>
        <td className="font-mono text-2xs text-ink-500">{shortHash(header.manifest_root)}</td>
        <td className="font-mono text-2xs text-ink-500">{shortHash(header.state_root)}</td>
        <td className="font-mono text-2xs text-ink-700">{shortHash(header.previous_hash, 8)}</td>
        <td>
          <div className="flex gap-1">
            {Object.keys(block.node_signatures).map((nodeId) => (
              <Badge key={nodeId} colour="#2fa36b" title="Ed25519 signature present">
                {nodeId}
              </Badge>
            ))}
            {Object.keys(block.node_signatures).length === 0 && (
              <span className="text-2xs text-ink-700">unsigned</span>
            )}
          </div>
        </td>
      </tr>
      {open && (
        <tr className="cursor-default">
          <td colSpan={8} className="bg-obsidian-850">
            <div className="p-3 space-y-2.5">
              <KeyValue
                columns={2}
                rows={[
                  ["block hash", header.block_hash],
                  ["previous hash", header.previous_hash],
                  ["manifest root", header.manifest_root],
                  ["route root", header.route_root],
                  ["state root", header.state_root],
                  ["records", String(header.record_count)],
                ]}
              />
              <div>
                <SectionLabel>Committed records — {block.record_ids.length}</SectionLabel>
                <div className="flex flex-wrap gap-1.5 max-h-28 overflow-y-auto">
                  {block.record_ids.map((id) => (
                    <button
                      key={id}
                      type="button"
                      className="font-mono text-2xs text-signal hover:underline"
                      onClick={() => onSelectRecord(id)}
                    >
                      {id}
                    </button>
                  ))}
                </div>
              </div>
              <p className="text-2xs text-ink-700 leading-relaxed">
                The block commits record <em>hashes</em>, never values. It can prove a
                record changed; it cannot say what the record used to contain. Finding
                the original value is the forensic engines' work — the chain only
                certifies the answer.
              </p>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
