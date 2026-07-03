# Large Restore Benchmark Summary

| Field | Value |
| --- | --- |
| Start time | 2026-07-03T21:42:38+01:00 |
| Memory size | 4096 MiB |
| Iterations | 10 |
| Full report | `./test/others/mem-snap/dump/large-restore-compare-10/report.log` |
| Results CSV | `./test/others/mem-snap/dump/large-restore-compare-10/results.csv` |
| Variants | 2 |

## Variants

| Variant | CRIU binary |
| --- | --- |
| without-change | `<without-change-worktree>/criu/criu` |
| with-change | `<with-change-worktree>/criu/criu` |

## Timing Summary

| Variant | Metric | Unit | Count | Mean | Median | Min | Max |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| without-change | dump_ms | ms | 10 | 1967.200 | 1974.500 | 1903 | 2016 |
| without-change | restore_ms | ms | 10 | 1730.600 | 1729.000 | 1704 | 1779 |
| without-change | criu_restore_time | us | 10 | 1726127.800 | 1724134.500 | 1699524 | 1774386 |
| with-change | dump_ms | ms | 10 | 1973.700 | 1980.500 | 1902 | 2026 |
| with-change | restore_ms | ms | 10 | 1742.400 | 1764.500 | 1566 | 1786 |
| with-change | criu_restore_time | us | 10 | 1738111.500 | 1759821.000 | 1561591 | 1781193 |

## Per-Iteration Results

| Variant | Iteration | Mem MiB | Dump ms | Restore ms | CRIU restore us | Pages restored | Path |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| without-change | 1 | 4096 | 2010 | 1727 | 1721946 | 1048608 | restorer-io |
| without-change | 2 | 4096 | 1976 | 1704 | 1699524 | 1048608 | restorer-io |
| without-change | 3 | 4096 | 1973 | 1713 | 1709074 | 1048606 | restorer-io |
| without-change | 4 | 4096 | 1922 | 1779 | 1774386 | 1048607 | restorer-io |
| without-change | 5 | 4096 | 1903 | 1735 | 1730236 | 1048606 | restorer-io |
| without-change | 6 | 4096 | 2016 | 1721 | 1717276 | 1048608 | restorer-io |
| without-change | 7 | 4096 | 1976 | 1734 | 1729896 | 1048606 | restorer-io |
| without-change | 8 | 4096 | 1997 | 1740 | 1734952 | 1048608 | restorer-io |
| without-change | 9 | 4096 | 1947 | 1731 | 1726323 | 1048606 | restorer-io |
| without-change | 10 | 4096 | 1952 | 1722 | 1717665 | 1048606 | restorer-io |
| with-change | 1 | 4096 | 1964 | 1729 | 1725255 | 1048607 | large-premap |
| with-change | 2 | 4096 | 1980 | 1764 | 1759347 | 1048608 | large-premap |
| with-change | 3 | 4096 | 1992 | 1775 | 1771413 | 1048607 | large-premap |
| with-change | 4 | 4096 | 1974 | 1784 | 1779447 | 1048607 | large-premap |
| with-change | 5 | 4096 | 1914 | 1767 | 1763231 | 1048606 | large-premap |
| with-change | 6 | 4096 | 1981 | 1566 | 1561591 | 1048606 | large-premap |
| with-change | 7 | 4096 | 1987 | 1765 | 1760295 | 1048607 | large-premap |
| with-change | 8 | 4096 | 1902 | 1734 | 1730039 | 1048606 | large-premap |
| with-change | 9 | 4096 | 2026 | 1754 | 1749304 | 1048607 | large-premap |
| with-change | 10 | 4096 | 2017 | 1786 | 1781193 | 1048607 | large-premap |

## Restore Path Evidence

| Variant | Iteration | nr_enqueued | Force premap markers | Large remaps | Path hint |
| --- | ---: | ---: | ---: | ---: | --- |
| without-change | 1 | 1040 | 0 | 0 | restorer-io |
| without-change | 2 | 1040 | 0 | 0 | restorer-io |
| without-change | 3 | 1041 | 0 | 0 | restorer-io |
| without-change | 4 | 1040 | 0 | 0 | restorer-io |
| without-change | 5 | 1040 | 0 | 0 | restorer-io |
| without-change | 6 | 1041 | 0 | 0 | restorer-io |
| without-change | 7 | 1040 | 0 | 0 | restorer-io |
| without-change | 8 | 1040 | 0 | 0 | restorer-io |
| without-change | 9 | 1040 | 0 | 0 | restorer-io |
| without-change | 10 | 1041 | 0 | 0 | restorer-io |
| with-change | 1 | 16 | 1 | 1 | large-premap |
| with-change | 2 | 15 | 1 | 1 | large-premap |
| with-change | 3 | 16 | 1 | 1 | large-premap |
| with-change | 4 | 15 | 1 | 1 | large-premap |
| with-change | 5 | 15 | 1 | 1 | large-premap |
| with-change | 6 | 16 | 1 | 1 | large-premap |
| with-change | 7 | 16 | 1 | 1 | large-premap |
| with-change | 8 | 15 | 1 | 1 | large-premap |
| with-change | 9 | 15 | 1 | 1 | large-premap |
| with-change | 10 | 16 | 1 | 1 | large-premap |
