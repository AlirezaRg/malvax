| sample | label | predicted | total median ms (IQR) | n |
|---|---|---|---|---|
| clean_text | negative | negative | 0.6718 (0.6112–0.7777) | 20 |
| clean_elf_stub | negative | negative | 0.8109 (0.7213–0.9115) | 20 |
| url_only | positive | positive | 0.6141 (0.5826–0.6541) | 20 |
| shell_only | positive | positive | 0.6889 (0.6597–0.7553) | 20 |
| yara_marker | positive | negative | 0.5955 (0.5771–0.619) | 20 |
| mixed_indicators | positive | positive | 0.6638 (0.648–0.7127) | 20 |

Confusion: {'tp': 3, 'fp': 0, 'tn': 2, 'fn': 1}
Precision: 1.0 · Recall: 0.75
Caveat: Synthetic samples with author-written labels. Measures detector/design consistency, not detection performance on real malware.