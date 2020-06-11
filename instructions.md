# Generating transaction data for plots

This toolchain fetches block and transaction graph data, performs iterative deducibility analysis, and produces month-by-month data for all transactions and deducible transactions by type.
It runs against any server supporting the [blockchain explorer](https://github.com/moneroexamples/onion-monero-blockchain-explorer) API, but should really be run locally for efficiency.

The fetch operation is incremental; if you point it at data files that already exist, it will continue from where you last left off.
Be sure that you never point it at an incomplete set of data files; it won't detect if your files don't match up.

In these examples, use whatever data file names you want, but be consistent.
For each tool, pass a `-h` flag to get help on how to run it.
Use only Python 3.

First, run the fetcher:

```bash
python3 fetch.py --server xmrchain.net --port 443 --tls 1 --file_transactions transactions.out --file_rings rings.out --file_outputs outputs.out
```

This will create (or update) the three data files: transaction data, ring data, and output data.
It will take longer than you expect, but will keep you updated on what it's doing.
If you want the entire chain, let it run until it's finished.
If you kill it before it's finished, you might have incomplete data; the tool will try to warn you if this happens during a write operation.
Further, the tool delays write operations until it has a full block of data, to reduce the likelihood of incomplete data being written in the event of a problem or abort.

Each line in the transaction data is of the form `index block type hash`; `index` is an internal reference counter, `block` is the block height, `type` is a reference to the classification of the transaction (described later in this document), and `hash` is the transaction hash on chain.

Each line in the ring data is of the form `transaction_index ring_index [keys]`; `transaction_index` refers to an index from the transaction file, `ring_index` is an internal reference counter for the transaction, and `[keys]` is a list of ring member keys.

Each line in the output data is of the form `transaction_index [keys]`; `transaction_index` refers to an index from the transaction file, and `[keys]` is a list of output keys.

Run the tracer against the appropriate data files:

```bash
python3 trace.py --file_transactions transactions.out --file_rings rings.out --file_trace trace.out
```

This will perform an iterative deducibility analysis and identify transactions containing at least one deducible ring.
The analysis may take up to a few dozen iteration rounds to complete.
The format of the trace data file is the same as that of the transaction data file.

To generate data suitable for plotting the number of transactions (either all transactions or just deducible ones) by type, run the plotter against either the transaction data (in this example, `transactions.out`) or the trace data (in this example, `trace.out`):

```bash
python3 plot.py --server xmrchain.net --port 443 --tls 1 --file_transactions trace.out --file_plot plot.out
```

This tool needs access to an explorer API server to build a mapping between timestamps and blocks.

Each line in the plot data looks something like this, with space separation:

```
2020-01 31 142 0
```

The first entry is a month in `YYYY-MM` format.
The second entry is the number of clear-type transactions (those with visible input and output amounts).
The third entry is the number of semi-type transactions (those with visible input amounts but hidden output amounts).
The fourth entry is the number of opaque-type transactions (those with hidden input and output amounts).

The set of transactions analyzed depends on which file you pass to the tool.
Since the transaction data and trace data files have the same format, the tool doesn't care which you use.
You can use the plot data in your favorite plotting tool.

Note that because of the way the deducibility analysis works, running the analysis on an incremental chain update might result in earlier counts increasing.
For this reason, it's best to use the entire resulting plot data, rather than simply appending new lines to your existing plots.
