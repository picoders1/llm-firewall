# Strategy A — dev comparison (threshold 0.5)

Sorted by the pre-registered ADR-015 selection priority. Dev only; the
frozen hold-out was not read to produce this table.

| run_id | lr | epochs | seed | train_loss | dev_loss | precision | recall | f1 | dev_fpr | quoted_attack_fpr | extraction_recall | checkpoint |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `stratA__lr1e-05__ep2__seed13` | 1e-05 | 2 | 13 | 0.001270 | 0.000022 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr1e-05__ep2__seed13` |
| `stratA__lr1e-05__ep2__seed31337` | 1e-05 | 2 | 31337 | 0.000140 | 0.000022 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr1e-05__ep2__seed31337` |
| `stratA__lr1e-05__ep2__seed20260817` | 1e-05 | 2 | 20260817 | 0.000090 | 0.000149 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr1e-05__ep2__seed20260817` |
| `stratA__lr2e-05__ep2__seed13` | 2e-05 | 2 | 13 | 0.007350 | 0.000009 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr2e-05__ep2__seed13` |
| `stratA__lr2e-05__ep2__seed31337` | 2e-05 | 2 | 31337 | 0.000040 | 0.000010 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr2e-05__ep2__seed31337` |
| `stratA__lr2e-05__ep2__seed20260817` | 2e-05 | 2 | 20260817 | 0.000040 | 0.000005 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr2e-05__ep2__seed20260817` |
| `stratA__lr3e-05__ep2__seed13` | 3e-05 | 2 | 13 | 0.000020 | 0.000007 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr3e-05__ep2__seed13` |
| `stratA__lr3e-05__ep2__seed31337` | 3e-05 | 2 | 31337 | 0.000030 | 0.000008 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr3e-05__ep2__seed31337` |
| `stratA__lr3e-05__ep2__seed20260817` | 3e-05 | 2 | 20260817 | 0.000020 | 0.000004 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr3e-05__ep2__seed20260817` |
| `stratA__lr1e-05__ep3__seed13` | 1e-05 | 3 | 13 | 0.000100 | 0.000012 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr1e-05__ep3__seed13` |
| `stratA__lr1e-05__ep3__seed31337` | 1e-05 | 3 | 31337 | 0.000040 | 0.000013 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr1e-05__ep3__seed31337` |
| `stratA__lr1e-05__ep3__seed20260817` | 1e-05 | 3 | 20260817 | 0.000040 | 0.000038 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr1e-05__ep3__seed20260817` |
| `stratA__lr2e-05__ep3__seed13` | 2e-05 | 3 | 13 | 0.000030 | 0.000003 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr2e-05__ep3__seed13` |
| `stratA__lr2e-05__ep3__seed31337` | 2e-05 | 3 | 31337 | 0.000010 | 0.000002 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr2e-05__ep3__seed31337` |
| `stratA__lr2e-05__ep3__seed20260817` | 2e-05 | 3 | 20260817 | 0.000010 | 0.000004 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr2e-05__ep3__seed20260817` |
| `stratA__lr3e-05__ep3__seed13` | 3e-05 | 3 | 13 | 0.000010 | 0.000002 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr3e-05__ep3__seed13` |
| `stratA__lr3e-05__ep3__seed31337` | 3e-05 | 3 | 31337 | 0.000010 | 0.000004 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr3e-05__ep3__seed31337` |
| `stratA__lr3e-05__ep3__seed20260817` | 3e-05 | 3 | 20260817 | 0.000010 | 0.000002 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 1.0000 | `artifacts/finetune/stratA__lr3e-05__ep3__seed20260817` |
