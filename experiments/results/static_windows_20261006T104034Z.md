| sample | label | predicted | total median ms (IQR) | n |
|---|---|---|---|---|
| clean_text | negative | negative | 0.5911 (0.566–0.7434) | 20 |
| clean_elf_stub | negative | negative | 0.607 (0.5996–0.6724) | 20 |
| url_only | positive | positive | 0.5908 (0.5813–0.6371) | 20 |
| shell_only | positive | positive | 0.5975 (0.5934–0.6115) | 20 |
| yara_marker | positive | positive | 0.5507 (0.5433–0.5709) | 20 |
| mixed_indicators | positive | positive | 0.65 (0.6252–0.7095) | 20 |

Confusion: {'tp': 4, 'fp': 0, 'tn': 2, 'fn': 0}
Precision: 1.0 · Recall: 1.0
Caveat: Synthetic samples with author-written labels. Measures detector/design consistency, not detection performance on real malware.