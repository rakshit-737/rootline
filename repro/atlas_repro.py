"""PyTorch reproduction of ATLAS (Alsaheel et al., USENIX Security 2021) under its own setup.

What is reused from ATLAS's shipped artefacts (``paper_experiments/Sx.zip``):
    * ``output/seq_graph_{training,testing}_*.dot.txt`` - the optimised causal-graph
      event statements their ``graph_generator.py`` produced (one ``subj rel obj`` per line).
    * ``{training,testing}_logs/<scenario>/malicious_labels.txt`` - entity ground truth.
    * ``output/eval_*.json`` - their own test-time output (for the "shipped artefact" column).

What is reimplemented (faithfully to ``atlas.py`` / ``evaluate.py``; no Keras code is executed):
    * active-statement filtering (``get_active_actions_statements``), sequence construction
      from entity subsets (``construct_seq_using_labels``), lemmatisation (``tokenize_sequences``,
      30-word vocabulary), training-set generation (``generate_malicious_sequences`` +
      ``suggest_ground_truth``), undersampling (fuzz.ratio >= 80, greedy) and oversampling
      (cyclic replication of attack sequences until balanced).
    * model: Embedding(31,128) -> Conv1D(64,k=5,relu) -> MaxPool1D(8) -> Dropout(0.2) -> LSTM(256)
      -> Dense(1,sigmoid); Adam(lr=1e-3), BCE, batch_size=1, 8 epochs, maxlen=400 (post-padding).
    * test: one investigation iteration from the symptom entity (``maximum_number_of_test_iterations=1``),
      each unknown entity e is scored by the model on seq({symptom, e}); predicted attack if p > 0.5.
    * entity-level metric of ``evaluate.py::process_file`` (substring matching, unique entities).

Usage (needs the ``repro`` extra: ``pip install -e ".[repro]"``; full training is CPU-heavy and
runs in the manual ``atlas-repro`` GitHub Actions workflow, one scenario x seed per job):
    python repro/atlas_repro.py --scenarios S1 --seed-list 0 --out results/atlas_repro_S1_0.json
    python repro/atlas_repro.py --merge results/atlas_repro_*.json --out results/atlas_repro.json
Data: ``$ROOTLINE_DATA/atlas`` (``python scripts/download_data.py --source atlas --split repro``).
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import random
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from itertools import combinations
from typing import Any

import numpy as np

MAXLEN = 400
VOCAB = ["process", "file", "IP_Address", "domain_name", "web_object", "read", "write", "delete", "execute",
         "executed", "fork", "connect", "resolve", "web_request", "refer", "combined_files", "windows_file",
         "windows_process", "system32_file", "system32_process", "programfiles_file", "programfiles_process",
         "user_file", "user_process", "bind", "sock_send", "connection", "connected_remote_ip", "session",
         "connected_session"]
TOK = {w: i + 1 for i, w in enumerate(VOCAB)}  # atlas.py: tokenized_elements, 1..30 (0 = padding)
LETTER = {i + 1: c for i, c in enumerate("abcdefghijklmnopqrstuvwxyzABCD")}  # tokenized_x_train_elements
MAX_FEATURES, EMB, FILTERS, KERNEL, POOL, LSTM_UNITS = 31, 128, 64, 5, 8, 256
EPOCHS, BATCH, U_THRESH = 8, 1, 80
WORKERS = 1  # parallel seed processes (each holds a model); --workers

# Paper, Table 4 ("Entity-based investigation results"), read from the USENIX PDF:
# (TP, TN, FP, FN, precision %, recall %, F1 %)
PAPER = {
    "S1": (22, 7445, 0, 0, 100.00, 100.00, 100.00),
    "S2": (12, 34008, 2, 0, 85.71, 100.00, 92.31),
    "S3": (24, 8972, 0, 2, 100.00, 92.31, 96.00),
    "S4": (21, 13011, 5, 0, 80.77, 100.00, 89.36),
    "M1": (28, 17562, 3, 0, 90.32, 100.00, 94.92),
    "M2": (36, 24445, 5, 0, 87.80, 100.00, 93.51),
    "M3": (35, 24423, 1, 1, 97.22, 97.22, 97.22),
    "M4": (24, 15378, 0, 4, 100.00, 85.71, 92.31),
    "M5": (30, 35665, 6, 0, 83.33, 100.00, 90.91),
    "M6": (41, 19573, 7, 1, 85.42, 97.62, 91.11),
}


# ----------------------------------------------------------------- lemmatisation
def _place(x: str, kind: str) -> str:
    for key, tag in (("c:/windows/system32", "system32"), ("c:/windows", "windows"),
                     ("c:/programfiles", "programfiles"), ("c:/users", "user")):
        if key in x:
            return f"{tag}_{kind}"
    return kind


def lemmatize(s: str, r: str, o: str) -> tuple[str, str, str]:
    """atlas.py::tokenize_sequences for one ``subject relation object`` triple."""
    if r in ("read", "write", "delete", "execute"):
        return _place(s, "process"), r, ("combined_files" if ";" in o else _place(o, "file"))
    if r == "fork":
        return _place(s, "process"), r, _place(o, "process")
    if r in ("connect", "bind"):
        return _place(s, "process"), r, ("connection" if r == "connect" else "session")
    if r == "resolve":
        return "IP_Address", r, "domain_name"
    if r == "web_request":
        return "domain_name", r, "web_object"
    if r == "refer":
        return "web_object", r, "web_object"
    if r == "executed":
        return _place(s, "file"), r, _place(o, "process")
    if r == "sock_send":
        return "session", r, "session"
    if r == "connected_remote_ip":
        return "IP_Address", r, ("connection" if o.startswith("connection_") else _place(o, "process"))
    if r == "connected_session":
        return "IP_Address", r, "session"
    return s, r, o  # unreachable for ATLAS's relation set (would KeyError in atlas.py)


# ----------------------------------------------------------------- graph file
class SeqGraph:
    """Active statements of one ``seq_graph_*.dot.txt`` plus fast subset -> sequence construction."""

    def __init__(self, path: str):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [ln.split() for ln in f if len(ln.split()) >= 3]
        # get_active_actions_statements
        subjects: list[str] = []
        seen: set[str] = set()
        for _s, r, o in (x[:3] for x in lines):
            if r in ("write", "connect") and o not in seen:
                seen.add(o)
                subjects.append(o)
        for s, _r, _o in (x[:3] for x in lines):
            if s not in seen:
                seen.add(s)
                subjects.append(s)
        stm, st_seen = [], set()
        for x in lines:
            if x[0] in seen and x[2] in seen:
                key = " ".join(x[:3])
                if key not in st_seen:
                    st_seen.add(key)
                    stm.append(tuple(x[:3]))
        self.statements: list[tuple[str, str, str]] = stm
        self.subjects = subjects
        self.tokens = [[TOK[w] for w in lemmatize(*t)] for t in stm]
        self._ends: dict[str, list[int]] = {}
        for i, (s, _r, o) in enumerate(stm):
            self._ends.setdefault(s, []).append(i)
            if o != s:
                self._ends.setdefault(o, []).append(i)
        self._cache: dict[str, frozenset[int]] = {}

    def lines_of(self, label: str) -> frozenset[int]:
        """Indices of statements whose subject or object contains ``label`` (substring, as atlas.py)."""
        got = self._cache.get(label)
        if got is None:
            idx: set[int] = set()
            for end, ii in self._ends.items():
                if label in end:
                    idx.update(ii)
            got = self._cache[label] = frozenset(idx)
        return got

    def seq(self, idx: set[int] | frozenset[int]) -> list[int]:
        out: list[int] = []
        for i in sorted(idx):
            out.extend(self.tokens[i])
        return out

    def union(self, labels: list[str]) -> frozenset[int]:
        acc: set[int] = set()
        for lab in labels:
            acc |= self.lines_of(lab)
        return frozenset(acc)


def read_labels(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return [x.strip().lower() for x in f.readlines()]  # atlas.py keeps blank lines too ("" matches all)


# ----------------------------------------------------------------- training set
def build_training_set(exp: str, log=print) -> dict[str, Any]:
    files = sorted(glob.glob(os.path.join(exp, "output", "seq_graph_training_preprocessed_logs_*.dot.txt")))
    pref = "seq_graph_training_preprocessed_logs_"
    graphs = []
    for fp in files:
        name = os.path.basename(fp)[len(pref):-len(".dot.txt")]
        labs = [x for x in read_labels(os.path.join(exp, "training_logs", name, "malicious_labels.txt")) if x]
        graphs.append((name, SeqGraph(fp), labs))
    # pass 1: generate_malicious_sequences for every (file, user_artifact)
    mal: set[tuple[int, ...]] = set()
    for _n, g, labs in graphs:
        for ua in labs:
            rest = [x for x in labs if x != ua]
            for r in range(1, len(rest) + 1):
                for combo in combinations(rest, r):
                    mal.add(tuple(g.seq(g.union([ua, *combo]))))
    # pass 2: suggest_ground_truth + prepare_dataset (global dedup on the tokenised sequence)
    seen: set[tuple[int, ...]] = set()
    xs: list[tuple[int, ...]] = []
    ys: list[int] = []
    for name, g, labs in graphs:
        for ua in labs:
            combo = [ua] + [x for x in labs if x != ua]
            while combo:
                base = g.union(combo)
                cs = set(combo)
                for lab in g.subjects:
                    if lab in cs:
                        continue
                    idx = base | g.lines_of(lab)
                    if 3 * len(idx) > MAXLEN:
                        continue
                    t = tuple(g.seq(idx))
                    if t in seen:
                        continue
                    seen.add(t)
                    xs.append(t)
                    ys.append(1 if t in mal else 0)
                combo = combo[:-1]
        log(f"  {name}: cumulative samples={len(xs)} attack={sum(ys)}")
    n_non = (len(xs), sum(ys))
    order = sorted(range(len(xs)), key=lambda i: ys[i], reverse=True)  # stable, attack first
    xs = [xs[i] for i in order]
    ys = [ys[i] for i in order]
    # undersampling: greedy, delete later non-attack sequences with fuzz.ratio >= 80 to a kept one
    from rapidfuzz import fuzz, process
    n1 = sum(ys)
    strs = ["".join(LETTER[t] for t in x) for x in xs]
    alive = np.ones(len(xs), dtype=bool)
    for i in range(n1, len(xs)):
        if not alive[i]:
            continue
        cand = np.nonzero(alive[i + 1:])[0] + i + 1
        if len(cand) == 0:
            break
        # fuzzywuzzy's ratio is round(100*r); ">= 80" therefore means raw score >= 79.5
        sc = process.cdist([strs[i]], [strs[j] for j in cand], scorer=fuzz.ratio, score_cutoff=79.5,
                           workers=-1)[0]
        alive[cand[sc >= 79.5]] = False
    keep = np.nonzero(alive)[0]
    xs = [xs[i] for i in keep]
    ys = [ys[i] for i in keep]
    n_under = (len(xs), sum(ys))
    # oversampling: prepend attack sequences cyclically until balanced
    n1, n0 = sum(ys), len(ys) - sum(ys)
    pos = xs[:n1]
    extra = [pos[k % n1] for k in range(n0 - n1)] if n1 else []
    xs = extra[::-1] + xs
    ys = [1] * len(extra) + ys
    return {"x": xs, "y": ys, "nonsampled": n_non, "undersampled": n_under, "resampled": (len(xs), sum(ys))}


def load_shipped_resampling(exp: str) -> dict[str, Any] | None:
    p = os.path.join(exp, "resampling", "resampling.json")
    if not os.path.exists(p):
        return None
    with open(p) as f:
        x, y, _z = json.load(f)
    return {"x": [tuple(v) for v in x], "y": list(y), "resampled": (len(x), sum(y))}


# ----------------------------------------------------------------- model
def make_model(seed: int):
    import torch
    from torch import nn

    torch.manual_seed(seed)

    class AtlasNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.emb = nn.Embedding(MAX_FEATURES, EMB)
            self.conv = nn.Conv1d(EMB, FILTERS, KERNEL)
            self.pool = nn.MaxPool1d(POOL)
            self.drop = nn.Dropout(0.2)
            self.lstm = nn.LSTM(FILTERS, LSTM_UNITS, batch_first=True)
            self.out = nn.Linear(LSTM_UNITS, 1)
            # Keras defaults: uniform(-0.05,0.05) embedding, glorot_uniform kernels, orthogonal recurrent,
            # zero biases, unit forget-gate bias.
            nn.init.uniform_(self.emb.weight, -0.05, 0.05)
            nn.init.xavier_uniform_(self.conv.weight)
            nn.init.zeros_(self.conv.bias)
            for k in range(4):
                nn.init.xavier_uniform_(self.lstm.weight_ih_l0.data[k * LSTM_UNITS:(k + 1) * LSTM_UNITS])
                nn.init.orthogonal_(self.lstm.weight_hh_l0.data[k * LSTM_UNITS:(k + 1) * LSTM_UNITS])
            nn.init.zeros_(self.lstm.bias_ih_l0)
            nn.init.zeros_(self.lstm.bias_hh_l0)
            self.lstm.bias_ih_l0.data[LSTM_UNITS:2 * LSTM_UNITS] = 1.0
            nn.init.xavier_uniform_(self.out.weight)
            nn.init.zeros_(self.out.bias)

        def forward(self, x):
            h = self.emb(x).transpose(1, 2)
            h = self.pool(torch.relu(self.conv(h)))
            h = self.drop(h).transpose(1, 2)
            _, (hn, _) = self.lstm(h)
            return self.out(hn[-1]).squeeze(-1)

    return AtlasNet()


def pad(seqs: list[tuple[int, ...]] | list[list[int]]) -> np.ndarray:
    """keras pad_sequences(padding='post', truncating='pre')."""
    out = np.zeros((len(seqs), MAXLEN), dtype=np.int64)
    for i, s in enumerate(seqs):
        s = list(s)[-MAXLEN:]
        out[i, :len(s)] = s
    return out


def train(xs, ys, seed: int, epochs: int = EPOCHS, batch: int = BATCH, log=print):
    import torch

    model = make_model(seed)
    comb = list(zip(xs, ys, strict=False))
    random.Random(seed).shuffle(comb)
    X = torch.from_numpy(pad([c[0] for c in comb]))
    Y = torch.tensor([c[1] for c in comb], dtype=torch.float32)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3, betas=(0.9, 0.999), eps=1e-7)
    lossf = torch.nn.BCEWithLogitsLoss()
    g = torch.Generator().manual_seed(seed)
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(len(X), generator=g)  # keras fit(shuffle=True)
        tot = 0.0
        for b in range(0, len(X), batch):
            ii = perm[b:b + batch]
            opt.zero_grad()
            loss = lossf(model(X[ii]), Y[ii])
            loss.backward()
            opt.step()
            tot += float(loss.detach()) * len(ii)
        log(f"    epoch {ep + 1}/{epochs} loss={tot / len(X):.4f}")
    model.eval()
    return model


def predict(model, seqs) -> np.ndarray:
    import torch

    out = []
    with torch.no_grad():
        X = torch.from_numpy(pad(seqs))
        for b in range(0, len(X), 512):
            out.append(torch.sigmoid(model(X[b:b + 512])).numpy())
    return np.concatenate(out) if out else np.zeros(0)


# ----------------------------------------------------------------- testing + evaluation
def _seed_job(args: tuple) -> tuple[int, list[float], float]:
    """Worker: train one seed and score the test sequences (runs in a separate process)."""
    import torch

    xs, ys, seed, epochs, batch, seqs, threads = args
    torch.set_num_threads(threads)
    t0 = time.perf_counter()
    model = train(xs, ys, seed, epochs, batch, log=lambda *_a: None)
    return seed, predict(model, seqs).tolist(), time.perf_counter() - t0


def test_candidates(g: SeqGraph, ua: str) -> tuple[list[str], list[tuple[int, ...]]]:
    """One ATLAS investigation iteration from the symptom entity: seq({ua, e}) for every unknown e."""
    base = g.lines_of(ua)
    words, seqs = [], []
    for lab in g.subjects:
        if lab == ua:
            continue
        idx = base | g.lines_of(lab)
        if 3 * len(idx) > MAXLEN or len(idx) == len(base):
            continue
        words.append(lab)
        seqs.append(tuple(g.seq(idx)))
    if 3 * len(base) <= MAXLEN:
        words.append(ua)
        seqs.append(tuple(g.seq(base)))
    return words, seqs


def entity_metrics(all_words: list[str], malicious: list[str], predicted: list[str]) -> dict[str, Any]:
    """evaluate.py::process_file + calculate_output, entity level (substring matching, unique counting)."""
    malicious = [m for m in malicious if m]
    predicted = [m for m in predicted if m]
    uniq = set(all_words)
    n_mal = sum(1 for w in uniq if any(m in w for m in malicious))
    fp_l: set[str] = set()
    fn_l: set[str] = set()
    for w in all_words:
        y = any(m in w for m in malicious)
        yhat = any(m in w for m in predicted)
        if yhat and not y:
            fp_l.add(w)
        if not yhat and y:
            fn_l.add(w)
    fp, fn = len(fp_l), len(fn_l)
    tp = n_mal - fn
    tn = len(uniq) - n_mal - fp
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1,
            "entities": len(uniq), "malicious_entities": n_mal}


def shipped_artefact(exp: str) -> dict[str, Any] | None:
    fs = glob.glob(os.path.join(exp, "output", "eval_seq_graph_testing_*.json"))
    if not fs:
        return None
    with open(fs[0]) as f:
        d = json.load(f)
    cleaned, mal, clue, words, pred = d[0], d[1], d[2], d[3], d[4]
    raw_pred = [w for w, p in zip(words, pred, strict=False) if p == 1] + [clue]
    return {
        "file": os.path.basename(fs[0]),
        "cleaned_predicted_entities": cleaned,
        "cleaned_equals_ground_truth": sorted(x for x in cleaned if x) == sorted(x for x in mal if x),
        "with_cleaned_list": entity_metrics(words, mal, cleaned),
        "raw_model_output": entity_metrics(words, mal, raw_pred),
        "raw_predicted_count": len(raw_pred),
    }


def rootline_entity_scores(root: str) -> dict[str, Any]:
    """ROOTLINE (unsupervised traversal) at entity level, via ``rootline.bench``.

    Same pivot as ``results/atlas.json`` (the ``user_artifact.txt`` IOC), reduced graph + ``trace_rootline``.
    An entity is a ROOTLINE *vertex*; a vertex is attack when ``entity_matches`` it to any ground-truth label.
    precision = attack vertices in the story / story vertices; recall = share of host-observable labels hit
    (identical to ``entity_recall`` in atlas.json). The universe is ROOTLINE's vertex set, not ATLAS's
    optimised-graph node set, so counts are not identical to ATLAS's TN/FP bookkeeping.
    """
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
    from rootline.bench import ioc_seeds, trace_rootline
    from rootline.loaders.atlas import discover, entity_matches, load_scenario
    from rootline.pipeline import build_graph
    from rootline.reduce import reduce_graph

    out = {}
    for d, name in discover(root):
        sc = load_scenario(d, name)
        raw, _ = build_graph(sc.records)
        seeds = ioc_seeds(raw, sc.artifacts[0] if sc.artifacts else "")
        if not seeds:
            continue
        red, _ = reduce_graph(raw, set(seeds))
        nodes = [n for n in trace_rootline(red, seeds) if n in raw.nodes]
        labs = sc.host_labels
        att = [n for n in nodes if any(entity_matches(raw.nodes[n].label, raw.nodes[n].attrs, lab) for lab in labs)]
        hit = sum(1 for lab in labs if any(entity_matches(raw.nodes[n].label, raw.nodes[n].attrs, lab) for n in nodes))
        p = len(att) / len(nodes) if nodes else 0.0
        r = hit / max(1, len(labs))
        out[name.split("-")[0]] = {"scenario": name, "story_vertices": len(nodes), "attack_vertices": len(att),
                                   "precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0}
    return out


def mean_ci(v: list[float]) -> tuple[float, float, float]:
    t975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}
    m = statistics.fmean(v)
    if len(v) < 2:
        return m, m, m
    h = t975.get(len(v) - 1, 1.96) * statistics.stdev(v) / math.sqrt(len(v))
    return m, max(0.0, m - h), min(1.0, m + h)


def find_experiments(root: str) -> dict[str, str]:
    out = {}
    for p in glob.glob(os.path.join(root, "**", "output", "seq_graph_testing_preprocessed_logs_*.dot.txt"),
                       recursive=True):
        sc = os.path.basename(p)[len("seq_graph_testing_preprocessed_logs_"):].split("-")[0]
        out.setdefault(sc, os.path.dirname(os.path.dirname(p)))
    return dict(sorted(out.items()))


def run_scenario(sc: str, exp: str, seeds: list[int], epochs: int, batch: int, use_shipped: bool,
                 log=print) -> dict[str, Any]:
    t0 = time.perf_counter()
    tf = glob.glob(os.path.join(exp, "output", "seq_graph_testing_preprocessed_logs_*.dot.txt"))[0]
    name = os.path.basename(tf)[len("seq_graph_testing_preprocessed_logs_"):-len(".dot.txt")]
    labels = [x for x in read_labels(os.path.join(exp, "testing_logs", name, "malicious_labels.txt")) if x]
    ua = labels[0]  # atlas.py: user_artifact = malicious_labels[0]
    log(f"[{sc}] building training set from {exp}")
    ts = build_training_set(exp, log)
    shipped_rs = load_shipped_resampling(exp)
    g = SeqGraph(tf)
    words, seqs = test_candidates(g, ua)
    res: dict[str, Any] = {
        "scenario": sc, "test": name, "symptom_entity": ua, "labels": labels,
        "candidate_entities": len(g.subjects), "scored_entities": len(words),
        "trainset": {k: ts[k] for k in ("nonsampled", "undersampled", "resampled")},
        "shipped_resampling": shipped_rs["resampled"] if shipped_rs else None,
        "paper": dict(zip(("tp", "tn", "fp", "fn", "precision", "recall", "f1"), PAPER[sc], strict=False)) if sc in PAPER else None,
        "shipped_artefact": shipped_artefact(exp),
        "runs": [],
    }
    variants = [("regenerated", ts)] + ([("shipped_resampling", shipped_rs)] if use_shipped and shipped_rs else [])
    for vname, data in variants:
        workers = max(1, min(len(seeds), WORKERS))
        threads = max(1, (os.cpu_count() or 2) // workers)
        jobs = [(data["x"], data["y"], s, epochs, batch, seqs, threads) for s in seeds]
        log(f"[{sc}] variant={vname} train n={len(data['x'])} seeds={seeds} ({workers} worker(s), {threads} thr each)")
        if workers == 1:
            done = [_seed_job(j) for j in jobs]
        else:
            with ProcessPoolExecutor(max_workers=workers) as ex:
                done = list(ex.map(_seed_job, jobs))
        for s, p, secs in done:
            pred_words = [w for w, q in zip(words, p, strict=False) if q > 0.5]
            if ua not in pred_words:
                pred_words.append(ua)  # the analyst-given symptom entity (evaluate.py clue_proba=1.0)
            m = entity_metrics(g.subjects, labels, pred_words)
            m.update({"variant": vname, "seed": s, "predicted": len(pred_words), "seconds": round(secs, 1)})
            log(f"[{sc}] {vname} seed={s}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} "
                f"(tp={m['tp']} fp={m['fp']} fn={m['fn']}, {secs:.0f}s)")
            res["runs"].append(m)
    res["summary"] = {}
    for vname, _ in variants:
        rows = [r for r in res["runs"] if r["variant"] == vname]
        res["summary"][vname] = {k: dict(zip(("mean", "lo", "hi"), mean_ci([r[k] for r in rows]), strict=False))
                                 for k in ("precision", "recall", "f1")}
    res["seconds"] = round(time.perf_counter() - t0, 1)
    return res


def _default_data() -> str:
    env = os.environ.get("ROOTLINE_DATA")
    return os.path.join(env, "atlas") if env else os.path.join(os.path.expanduser("~"), ".cache", "rootline", "atlas")


def merge(paths: list[str]) -> dict[str, Any]:
    """Merge per-(scenario, seed) result files from the CI matrix into one summary."""
    parts = [json.load(open(p)) for p in sorted(paths)]
    out = {k: parts[0][k] for k in ("setup", "paper_table4_entity")}
    out["setup"]["seeds"] = sorted({s for p in parts for s in p["setup"]["seeds"]})
    by: dict[str, dict[str, Any]] = {}
    for p in parts:
        for sc in p["scenarios"]:
            cur = by.setdefault(sc["scenario"], {k: v for k, v in sc.items() if k not in ("runs", "summary", "seconds")})
            cur.setdefault("runs", []).extend(sc["runs"])
        if "rootline_entity" in p:
            out["rootline_entity"] = p["rootline_entity"]
    for sc in by.values():
        sc["summary"] = {}
        for vname in sorted({r["variant"] for r in sc["runs"]}):
            rows = [r for r in sc["runs"] if r["variant"] == vname]
            sc["summary"][vname] = {k: dict(zip(("mean", "lo", "hi"), mean_ci([r[k] for r in rows]), strict=False))
                                    for k in ("precision", "recall", "f1")} | {"n_seeds": len(rows)}
    out["scenarios"] = [by[k] for k in sorted(by)]
    return out


def main(argv: list[str] | None = None) -> int:
    global WORKERS
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", default=_default_data(), help="ATLAS folder (default $ROOTLINE_DATA/atlas)")
    ap.add_argument("--seeds", type=int, default=5, help="seeds 0..N-1 (ignored with --seed-list)")
    ap.add_argument("--seed-list", default="", help="comma list of seeds, e.g. 0 or 0,1")
    ap.add_argument("--workers", type=int, default=1, help="seed processes in parallel (each holds a model)")
    ap.add_argument("--merge", nargs="+", help="merge these per-job result files into --out and exit")
    ap.add_argument("--epochs", type=int, default=EPOCHS)
    ap.add_argument("--batch", type=int, default=BATCH,
                    help="ATLAS uses 1 (atlas.py batch_size=1), the default here")
    ap.add_argument("--scenarios", default="", help="comma list, e.g. S1,S3 (default: all found)")
    ap.add_argument("--shipped-resampling", action="store_true",
                    help="also train on ATLAS's shipped resampling/resampling.json where present")
    ap.add_argument("--rootline", action="store_true", help="also score ROOTLINE at entity level (rootline.bench)")
    ap.add_argument("--no-train", action="store_true", help="skip model training (artefact + ROOTLINE only)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "results", "atlas_repro.json"))
    a = ap.parse_args(argv)
    WORKERS = a.workers
    if a.merge:
        merged = merge(a.merge)
        with open(a.out, "w") as f:
            json.dump(merged, f, indent=1)
        print(f"merged {len(a.merge)} files -> {a.out}")
        return 0
    seeds = [int(x) for x in a.seed_list.split(",") if x] if a.seed_list else list(range(a.seeds))
    exps = find_experiments(a.data)
    if a.scenarios:
        exps = {k: v for k, v in exps.items() if k in a.scenarios.split(",")}
    if not exps:
        print(f"no ATLAS experiments under {a.data}", file=sys.stderr)
        return 1
    out = {"setup": {"maxlen": MAXLEN, "embedding": EMB, "conv_filters": FILTERS, "kernel": KERNEL, "pool": POOL,
                     "lstm": LSTM_UNITS, "dropout": 0.2, "epochs": a.epochs, "batch_size": a.batch,
                     "optimizer": "adam(lr=1e-3)", "threshold": 0.5, "undersampling_fuzz_ratio": U_THRESH,
                     "seeds": seeds, "test_iterations": 1},
           "paper_table4_entity": {k: dict(zip(("tp", "tn", "fp", "fn", "precision", "recall", "f1"), v, strict=False))
                                   for k, v in PAPER.items()},
           "scenarios": []}
    if a.rootline:
        out["rootline_entity"] = rootline_entity_scores(a.data)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    for sc, exp in ({} if a.no_train else exps).items():
        out["scenarios"].append(run_scenario(sc, exp, seeds, a.epochs, a.batch, a.shipped_resampling))
        with open(a.out, "w") as f:  # after each scenario, so a timeout keeps finished work
            json.dump(out, f, indent=1)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1)
    print(f"wrote {os.path.abspath(a.out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
