# UOV chip-RTL matrix

Last updated: 2026-11-17: chip tables from the reruns rtl-2026-11 (128 KiB) and rtl-2026-11b (32 KiB); the chip tests copy their data faster, so host I/O is lower.

Every chip test of `sw/device/tests/acc_uov/`, from the records in this directory. Written by
`python3 tools/uov.py tables`; do not edit. How to run the tests and what each meter is:
`sw/device/tests/acc_uov/README.md`. The accepting run of a test uses one KAT case: keygen and sign
case 0, verify case 11. `tuned` is the shipping kernel, the
tests named `stream`. The speed-ups over sw are in `README.md` and `COMPARISONS.md`.

## 32 KiB DMEM profile

<!-- table:rtl:all@32 -->
| DMEM | op | kernel | param | tier | ACC instructions | exec+wait | host I/O + fold | whole operation | app load | whole test |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|
| 32 KiB | keygen | stream_uniform | Ip | bngfaes | 1,918,881 | 2,430,617 | 223,200 | 2,655,753 | 446,357 | 6,838,283 |
| 32 KiB | keygen | stream_uniform | Ip | bngfonly | 42,703,335 | 43,862,338 | 223,194 | 44,087,465 | 465,816 | 48,322,571 |
| 32 KiB | keygen | stream_uniform | Ip | bnaesonly | 34,584,845 | 35,774,760 | 223,194 | 35,999,887 | 504,306 | 40,312,843 |
| 32 KiB | keygen | stream_uniform | Ip | sw | 120,051,874 | 140,074,450 | 223,194 | 140,299,577 | 556,645 | 144,711,691 |
| 32 KiB | keygen | stream_uniform | Is | bngfaes | 2,083,348 | 2,652,963 | 343,638 | 2,998,173 | 442,444 | 7,374,859 |
| 32 KiB | keygen | stream_uniform | Is | bngfonly | 36,983,983 | 38,028,908 | 343,653 | 38,374,161 | 462,275 | 42,799,115 |
| 32 KiB | keygen | stream_uniform | Is | bnaesonly | 32,836,529 | 35,171,911 | 343,715 | 35,517,243 | 458,302 | 39,933,963 |
| 32 KiB | keygen | stream_uniform | Is | sw | 106,125,325 | 124,807,009 | 343,656 | 125,152,201 | 530,345 | 129,712,139 |
| 32 KiB | keygen | stream_uniform | Ip3 | bngfaes | 2,343,426 | 2,800,729 | 308,094 | 3,110,696 | 494,653 | 7,454,731 |
| 32 KiB | keygen | stream_uniform | Ip3 | bngfonly | 53,691,162 | 55,074,272 | 308,129 | 55,384,236 | 518,753 | 59,789,323 |
| 32 KiB | keygen | stream_uniform | Ip3 | bnaesonly | 40,150,614 | 41,214,935 | 308,094 | 41,524,901 | 530,327 | 45,955,083 |
| 32 KiB | keygen | stream_uniform | Ip3 | sw | 147,607,773 | 172,453,779 | 308,094 | 172,763,745 | 606,577 | 177,340,427 |
| 32 KiB | keygen | tuned | Ip | bngfaes | 1,677,514 | 2,022,802 | 222,459 | 2,246,823 | 574,823 | 6,496,267 |
| 32 KiB | keygen | tuned | Ip | bngfonly | 34,069,380 | 34,892,775 | 222,459 | 35,116,795 | 585,803 | 39,399,435 |
| 32 KiB | keygen | tuned | Ip | bnaesonly | 34,427,677 | 35,454,888 | 223,194 | 35,680,015 | 501,073 | 39,968,779 |
| 32 KiB | keygen | tuned | Ip | sw | 119,894,706 | 139,755,053 | 223,200 | 139,980,189 | 553,412 | 144,357,387 |
| 32 KiB | keygen | tuned | Is | bngfaes | 1,958,603 | 2,360,831 | 343,270 | 2,705,494 | 533,334 | 7,165,963 |
| 32 KiB | keygen | tuned | Is | bngfonly | 32,666,735 | 33,487,309 | 343,334 | 33,832,067 | 545,410 | 38,322,187 |
| 32 KiB | keygen | tuned | Is | bnaesonly | 32,499,216 | 34,687,166 | 343,713 | 35,032,490 | 474,894 | 39,471,115 |
| 32 KiB | keygen | tuned | Is | sw | 105,788,012 | 124,322,264 | 343,656 | 124,667,456 | 546,937 | 129,245,195 |
| 32 KiB | keygen | tuned | Ip3 | bngfaes | 2,142,918 | 2,571,832 | 307,709 | 2,881,227 | 577,661 | 7,282,699 |
| 32 KiB | keygen | tuned | Ip3 | bngfonly | 48,289,144 | 49,550,088 | 307,753 | 49,859,513 | 591,462 | 54,300,683 |
| 32 KiB | keygen | tuned | Ip3 | bnaesonly | 40,049,651 | 41,101,776 | 308,129 | 41,411,758 | 525,020 | 45,801,483 |
| 32 KiB | keygen | tuned | Ip3 | sw | 147,511,532 | 172,350,132 | 308,065 | 172,660,033 | 601,769 | 177,199,115 |
| 32 KiB | sign | ldirect | Ip | bngfaes | 233,912 | 270,381 | 802 | 271,215 | 425,074 | 3,690,507 |
| 32 KiB | sign | ldirect | Ip | bngfonly | 6,937,931 | 7,102,205 | 802 | 7,103,039 | 449,718 | 24,264,715 |
| 32 KiB | sign | ldirect | Ip | bnaesonly | 2,132,033 | 2,245,645 | 802 | 2,246,479 | 453,927 | 9,711,627 |
| 32 KiB | sign | ldirect | Ip | sw | 16,095,016 | 19,285,357 | 802 | 19,286,191 | 506,265 | 60,975,115 |
| 32 KiB | sign | ldirect | Is | bngfaes | 256,577 | 284,865 | 716 | 285,613 | 238,536 | 3,172,363 |
| 32 KiB | sign | ldirect | Is | bngfonly | 10,063,693 | 10,243,193 | 716 | 10,243,941 | 256,836 | 33,112,075 |
| 32 KiB | sign | ldirect | Is | bnaesonly | 1,449,563 | 1,557,009 | 716 | 1,557,757 | 261,289 | 7,065,611 |
| 32 KiB | sign | ldirect | Is | sw | 22,067,072 | 26,753,729 | 716 | 26,754,477 | 334,428 | 82,862,091 |
| 32 KiB | sign | ldirect | Ip3 | bngfaes | 288,461 | 340,471 | 868 | 341,372 | 412,262 | 3,866,635 |
| 32 KiB | sign | ldirect | Ip3 | bngfonly | 8,649,789 | 8,860,171 | 868 | 8,861,072 | 435,259 | 29,499,403 |
| 32 KiB | sign | ldirect | Ip3 | bnaesonly | 2,301,572 | 2,399,731 | 868 | 2,400,632 | 467,894 | 10,219,531 |
| 32 KiB | sign | ldirect | Ip3 | sw | 19,796,805 | 23,767,441 | 868 | 23,768,342 | 541,582 | 74,530,827 |
| 32 KiB | verify | stream_uniform | Ip | bngfaes | 172,811 | 197,081 | 61,608 | 259,185 | 354,866 | 3,594,251 |
| 32 KiB | verify | stream_uniform | Ip | bngfonly | 7,253,298 | 7,366,358 | 61,608 | 7,428,462 | 371,581 | 17,977,355 |
| 32 KiB | verify | stream_uniform | Ip | bnaesonly | 1,238,279 | 1,291,934 | 61,608 | 1,354,037 | 391,293 | 5,873,675 |
| 32 KiB | verify | stream_uniform | Ip | sw | 15,211,952 | 18,350,460 | 61,608 | 18,412,564 | 458,213 | 40,103,947 |
| 32 KiB | verify | stream_uniform | Is | bngfaes | 164,425 | 169,322 | 90,989 | 261,046 | 428,654 | 3,840,011 |
| 32 KiB | verify | stream_uniform | Is | bngfonly | 9,906,755 | 10,041,231 | 90,978 | 10,132,944 | 446,853 | 23,629,835 |
| 32 KiB | verify | stream_uniform | Is | bnaesonly | 806,652 | 881,192 | 90,978 | 972,905 | 447,280 | 5,308,427 |
| 32 KiB | verify | stream_uniform | Is | sw | 21,380,961 | 26,002,306 | 90,978 | 26,094,019 | 518,406 | 55,699,467 |
| 32 KiB | verify | stream_uniform | Ip3 | bngfaes | 213,045 | 242,592 | 66,005 | 309,095 | 408,786 | 3,825,675 |
| 32 KiB | verify | stream_uniform | Ip3 | bngfonly | 7,976,256 | 8,128,623 | 66,005 | 8,195,136 | 430,120 | 19,650,571 |
| 32 KiB | verify | stream_uniform | Ip3 | bnaesonly | 1,410,196 | 1,471,193 | 66,006 | 1,537,700 | 464,502 | 6,410,251 |
| 32 KiB | verify | stream_uniform | Ip3 | sw | 18,845,889 | 22,755,989 | 66,006 | 22,822,507 | 532,987 | 49,096,715 |
| 32 KiB | verify | tuned | Ip | bngfaes | 150,147 | 157,959 | 61,608 | 220,062 | 54,341 | 2,922,507 |
| 32 KiB | verify | tuned | Ip | bngfonly | 7,249,790 | 7,360,928 | 61,608 | 7,423,031 | 370,317 | 17,938,443 |
| 32 KiB | verify | tuned | Ip | bnaesonly | 1,208,897 | 1,250,461 | 61,608 | 1,312,564 | 378,183 | 5,734,411 |
| 32 KiB | verify | tuned | Ip | sw | 15,200,606 | 18,335,084 | 61,608 | 18,397,188 | 447,551 | 40,028,171 |
| 32 KiB | verify | tuned | Is | bngfaes | 164,342 | 169,206 | 90,989 | 260,930 | 11,784 | 2,998,283 |
| 32 KiB | verify | tuned | Is | bngfonly | 9,906,753 | 10,041,231 | 90,978 | 10,132,944 | 509,622 | 23,746,571 |
| 32 KiB | verify | tuned | Is | bnaesonly | 806,628 | 881,259 | 90,978 | 972,972 | 379,448 | 5,167,115 |
| 32 KiB | verify | tuned | Is | sw | 21,380,937 | 26,002,373 | 90,978 | 26,094,086 | 451,001 | 55,558,155 |
| 32 KiB | verify | tuned | Ip3 | bngfaes | 187,215 | 198,109 | 66,004 | 264,618 | 163,509 | 3,221,515 |
| 32 KiB | verify | tuned | Ip3 | bngfonly | 7,943,337 | 8,077,028 | 66,006 | 8,143,545 | 544,354 | 19,750,923 |
| 32 KiB | verify | tuned | Ip3 | bnaesonly | 1,410,173 | 1,471,202 | 66,006 | 1,537,706 | 463,549 | 6,383,627 |
| 32 KiB | verify | tuned | Ip3 | sw | 18,845,866 | 22,755,953 | 66,006 | 22,822,460 | 532,053 | 49,070,091 |

Instructions the ACC retired, then Ibex cycles.
Chip RTL under Verilator, 32 KiB DMEM profile, the accepting run of each test. Measured 2026-11-16 to 2026-11-17 at `9fe0ccdd8c` (rtl-2026-11b).
<!-- /table:rtl:all@32 -->

### Against the ISS
The keygen and verify tests run the ELF the ISS measures; the sign tests run their own harness
(`sign_rtl`), so they are not in this table.

<!-- table:rtl-iss:all@32 -->
| DMEM | op | kernel | param | tier | ACC instructions | ISS cases with that count | exec+wait above the ISS cycles |
|---|---|---|---|---|---:|---|---:|
| 32 KiB | keygen | stream_uniform | Ip | bngfaes | 1,918,881 | 0-11 | 5,794 |
| 32 KiB | keygen | stream_uniform | Ip | bngfonly | 42,703,335 | 0-11 | 5,844 |
| 32 KiB | keygen | stream_uniform | Ip | bnaesonly | 34,584,845 | 0-11 | 5,827 |
| 32 KiB | keygen | stream_uniform | Ip | sw | 120,051,874 | 0-11 | 5,611 |
| 32 KiB | keygen | stream_uniform | Is | bngfaes | 2,083,348 | 0-11 | 4,435 |
| 32 KiB | keygen | stream_uniform | Is | bngfonly | 36,983,983 | 0-11 | 4,576 |
| 32 KiB | keygen | stream_uniform | Is | bnaesonly | 32,836,529 | 0-11 | 4,759 |
| 32 KiB | keygen | stream_uniform | Is | sw | 106,125,325 | 0-11 | 4,497 |
| 32 KiB | keygen | stream_uniform | Ip3 | bngfaes | 2,343,426 | 0-11 | 5,822 |
| 32 KiB | keygen | stream_uniform | Ip3 | bngfonly | 53,691,162 | 0-11 | 5,719 |
| 32 KiB | keygen | stream_uniform | Ip3 | bnaesonly | 40,150,614 | 0-11 | 5,740 |
| 32 KiB | keygen | stream_uniform | Ip3 | sw | 147,607,773 | 0-11 | 5,739 |
| 32 KiB | keygen | tuned | Ip | bngfaes | 1,677,514 | 0-11 | 4,718 |
| 32 KiB | keygen | tuned | Ip | bngfonly | 34,069,380 | 0-11 | 4,473 |
| 32 KiB | keygen | tuned | Ip | bnaesonly | 34,427,677 | 0-11 | 5,682 |
| 32 KiB | keygen | tuned | Ip | sw | 119,894,706 | 0-11 | 5,941 |
| 32 KiB | keygen | tuned | Is | bngfaes | 1,958,603 | 0-11 | 4,086 |
| 32 KiB | keygen | tuned | Is | bngfonly | 32,666,735 | 0-11 | 4,166 |
| 32 KiB | keygen | tuned | Is | bnaesonly | 32,499,216 | 0-11 | 4,767 |
| 32 KiB | keygen | tuned | Is | sw | 105,788,012 | 0-11 | 4,505 |
| 32 KiB | keygen | tuned | Ip3 | bngfaes | 2,142,918 | 0-11 | 5,152 |
| 32 KiB | keygen | tuned | Ip3 | bngfonly | 48,289,144 | 0-11 | 5,067 |
| 32 KiB | keygen | tuned | Ip3 | bnaesonly | 40,049,651 | 0-11 | 5,690 |
| 32 KiB | keygen | tuned | Ip3 | sw | 147,511,532 | 0-11 | 5,781 |
| 32 KiB | verify | stream_uniform | Ip | bngfaes | 172,811 | 11 | 2,218 |
| 32 KiB | verify | stream_uniform | Ip | bngfonly | 7,253,298 | 11 | 2,129 |
| 32 KiB | verify | stream_uniform | Ip | bnaesonly | 1,238,279 | 11 | 2,228 |
| 32 KiB | verify | stream_uniform | Ip | sw | 15,211,952 | 11 | 2,211 |
| 32 KiB | verify | stream_uniform | Is | bngfaes | 164,425 | 11 | 2,702 |
| 32 KiB | verify | stream_uniform | Is | bngfonly | 9,906,755 | 11 | 2,645 |
| 32 KiB | verify | stream_uniform | Is | bnaesonly | 806,652 | 11 | 2,614 |
| 32 KiB | verify | stream_uniform | Is | sw | 21,380,961 | 11 | 2,624 |
| 32 KiB | verify | stream_uniform | Ip3 | bngfaes | 213,045 | 11 | 2,214 |
| 32 KiB | verify | stream_uniform | Ip3 | bngfonly | 7,976,256 | 11 | 2,186 |
| 32 KiB | verify | stream_uniform | Ip3 | bnaesonly | 1,410,196 | 11 | 2,183 |
| 32 KiB | verify | stream_uniform | Ip3 | sw | 18,845,889 | 11 | 2,208 |
| 32 KiB | verify | tuned | Ip | bngfaes | 150,147 | 11 | 2,183 |
| 32 KiB | verify | tuned | Ip | bngfonly | 7,249,790 | 11 | 2,156 |
| 32 KiB | verify | tuned | Ip | bnaesonly | 1,208,897 | 11 | 2,154 |
| 32 KiB | verify | tuned | Ip | sw | 15,200,606 | 11 | 2,182 |
| 32 KiB | verify | tuned | Is | bngfaes | 164,342 | 11 | 2,700 |
| 32 KiB | verify | tuned | Is | bngfonly | 9,906,753 | 11 | 2,653 |
| 32 KiB | verify | tuned | Is | bnaesonly | 806,628 | 11 | 2,715 |
| 32 KiB | verify | tuned | Is | sw | 21,380,937 | 11 | 2,725 |
| 32 KiB | verify | tuned | Ip3 | bngfaes | 187,215 | 11 | 2,247 |
| 32 KiB | verify | tuned | Ip3 | bngfonly | 7,943,337 | 11 | 2,179 |
| 32 KiB | verify | tuned | Ip3 | bnaesonly | 1,410,173 | 11 | 2,224 |
| 32 KiB | verify | tuned | Ip3 | sw | 18,845,866 | 11 | 2,204 |

Instructions the ACC retired in each chip test, the cases whose ISS run of the same ELF retires exactly as many,
and how far the chip's exec+wait lies above the ISS cycles of the first such case (none: no case has that count).
Chip RTL under Verilator and the ISS, 32 KiB DMEM profile. Measured 2026-11-01 to 2026-11-17 at `7ca6de3b2e`, `9fe0ccdd8c` (iss-2026-10j, rtl-2026-11b).
<!-- /table:rtl-iss:all@32 -->

## 128 KiB DMEM profile (one-shot kernels)

<!-- table:rtl:all@128 -->
| DMEM | op | kernel | param | tier | ACC instructions | exec+wait | host I/O + fold | whole operation | app load | whole test |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|
| 128 KiB | keygen | min | Ip | bngfaes | 2,924,593 | 3,557,153 | 57,523 | 3,614,692 | 1,013,223 | 17,604,619 |
| 128 KiB | keygen | min | Ip | bngfonly | 95,171,341 | 97,267,853 | 57,523 | 97,325,392 | 1,036,142 | 298,770,443 |
| 128 KiB | keygen | min | Ip | bnaesonly | 36,353,430 | 37,929,188 | 57,519 | 37,986,719 | 1,030,802 | 42,321,931 |
| 128 KiB | keygen | min | Ip | sw | 229,660,916 | 273,832,619 | 57,519 | 273,890,150 | 1,083,101 | 278,267,915 |
| 128 KiB | keygen | min | Is | bngfaes | 3,686,859 | 4,387,913 | 87,714 | 4,475,641 | 1,229,945 | 22,487,051 |
| 128 KiB | keygen | min | Is | bngfonly | 143,425,995 | 146,014,768 | 87,714 | 146,102,496 | 1,244,735 | 447,404,043 |
| 128 KiB | keygen | min | Is | bnaesonly | 34,041,272 | 36,667,714 | 87,736 | 36,755,460 | 1,239,351 | 42,121,227 |
| 128 KiB | keygen | min | Is | sw | 330,196,205 | 398,600,301 | 87,736 | 398,688,047 | 1,312,484 | 404,119,563 |
| 128 KiB | keygen | min | Ip3 | bngfaes | 6,161,233 | 6,804,005 | 61,486 | 6,865,507 | 1,058,718 | 27,654,155 |
| 128 KiB | keygen | min | Ip3 | bngfonly | 244,653,493 | 249,596,848 | 61,486 | 249,658,350 | 1,084,320 | 756,078,603 |
| 128 KiB | keygen | min | Ip3 | bnaesonly | 44,682,538 | 46,034,993 | 61,489 | 46,096,494 | 1,051,152 | 50,569,227 |
| 128 KiB | keygen | min | Ip3 | sw | 543,798,913 | 655,629,584 | 61,489 | 655,691,085 | 1,127,846 | 660,232,203 |
| 128 KiB | keygen | sp | Ip | bngfaes | 1,284,994 | 1,652,759 | 57,523 | 1,710,298 | 1,432,744 | 12,888,075 |
| 128 KiB | keygen | sp | Ip | bngfonly | 9,202,320 | 9,695,746 | 57,523 | 9,753,285 | 1,455,630 | 37,046,283 |
| 128 KiB | keygen | sp | Ip | bnaesonly | 33,579,442 | 34,490,780 | 57,540 | 34,548,330 | 1,449,285 | 39,884,811 |
| 128 KiB | keygen | sp | Ip | sw | 50,172,171 | 54,739,684 | 57,540 | 54,797,234 | 1,501,626 | 60,174,347 |
| 128 KiB | keygen | sp | Is | bngfaes | 1,795,872 | 2,228,489 | 87,714 | 2,316,217 | 1,291,833 | 16,275,467 |
| 128 KiB | keygen | sp | Is | bngfonly | 11,537,400 | 12,106,400 | 87,714 | 12,194,128 | 1,306,783 | 45,938,699 |
| 128 KiB | keygen | sp | Is | bnaesonly | 31,636,354 | 33,702,027 | 87,713 | 33,789,750 | 1,300,972 | 39,430,155 |
| 128 KiB | keygen | sp | Is | sw | 52,253,863 | 58,898,684 | 87,713 | 58,986,407 | 1,374,114 | 64,690,187 |
| 128 KiB | keygen | sp | Ip3 | bngfaes | 1,641,122 | 2,080,056 | 61,486 | 2,141,558 | 1,527,839 | 14,532,619 |
| 128 KiB | keygen | sp | Ip3 | bngfonly | 11,398,758 | 12,013,616 | 61,486 | 12,075,118 | 1,553,459 | 44,371,979 |
| 128 KiB | keygen | sp | Ip3 | bnaesonly | 39,346,543 | 40,381,785 | 61,495 | 40,443,290 | 1,519,667 | 45,969,419 |
| 128 KiB | keygen | sp | Ip3 | sw | 59,769,010 | 65,324,623 | 61,495 | 65,386,128 | 1,596,415 | 70,977,547 |
| 128 KiB | verify | full | Ip | bngfaes | 150,144 | 156,362 | 59,380 | 215,856 | 749,879 | 27,248,651 |
| 128 KiB | verify | full | Ip | bngfonly | 7,249,728 | 7,359,272 | 59,380 | 7,418,766 | 740,058 | 178,515,979 |
| 128 KiB | verify | full | Ip | bnaesonly | 1,208,825 | 1,248,769 | 59,380 | 1,308,263 | 749,147 | 50,202,635 |
| 128 KiB | verify | full | Ip | sw | 15,200,534 | 18,333,377 | 59,380 | 18,392,871 | 826,312 | 409,045,003 |
| 128 KiB | verify | full | Is | bngfaes | 164,308 | 166,990 | 89,186 | 256,289 | 1,048,340 | 36,610,059 |
| 128 KiB | verify | full | Is | bngfonly | 9,906,637 | 10,038,958 | 89,186 | 10,128,257 | 1,066,457 | 234,082,315 |
| 128 KiB | verify | full | Is | bnaesonly | 806,506 | 878,929 | 89,186 | 968,233 | 1,065,806 | 50,894,859 |
| 128 KiB | verify | full | Is | sw | 21,380,815 | 26,000,051 | 89,186 | 26,089,355 | 1,137,349 | 553,375,755 |
| 128 KiB | verify | full | Ip3 | bngfaes | 187,185 | 196,359 | 63,328 | 259,800 | 906,722 | 29,577,227 |
| 128 KiB | verify | full | Ip3 | bngfonly | 7,943,248 | 8,075,279 | 63,328 | 8,138,720 | 933,257 | 195,078,155 |
| 128 KiB | verify | full | Ip3 | bnaesonly | 1,410,102 | 1,469,449 | 63,328 | 1,532,890 | 845,051 | 56,262,667 |
| 128 KiB | verify | full | Ip3 | sw | 18,845,795 | 22,754,209 | 63,328 | 22,817,650 | 918,800 | 503,310,347 |

Instructions the ACC retired, then Ibex cycles.
Chip RTL under Verilator, 128 KiB DMEM profile, the accepting run of each test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl:all@128 -->

### Every timed run
The keygen tests of the hardware-GF tiers run seed A, seed B and seed A again on one loaded image;
the verify tests run accept, reject and accept with the key resident.

<!-- table:rtl-runs:keygen/sp@128 -->
| DMEM | param | tier | accept | restart_b | restart_a2 |
|---|---|---|---:|---:|---:|
| 128 KiB | Ip | bngfaes | 1,652,759 | 1,652,785 | 1,652,776 |
| 128 KiB | Ip | bngfonly | 9,695,746 | 9,695,713 | 9,695,690 |
| 128 KiB | Ip | bnaesonly | 34,490,780 | - | - |
| 128 KiB | Ip | sw | 54,739,684 | - | - |
| 128 KiB | Is | bngfaes | 2,228,489 | 2,228,468 | 2,228,445 |
| 128 KiB | Is | bngfonly | 12,106,400 | 12,106,361 | 12,106,356 |
| 128 KiB | Is | bnaesonly | 33,702,027 | - | - |
| 128 KiB | Is | sw | 58,898,684 | - | - |
| 128 KiB | Ip3 | bngfaes | 2,080,056 | 2,080,011 | 2,080,001 |
| 128 KiB | Ip3 | bngfonly | 12,013,616 | 12,013,571 | 12,013,571 |
| 128 KiB | Ip3 | bnaesonly | 40,381,785 | - | - |
| 128 KiB | Ip3 | sw | 65,324,623 | - | - |

exec+wait in Ibex cycles of every timed run of each test; - where a test does not make that run.
Chip RTL under Verilator, 128 KiB DMEM profile, one loaded image per test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-runs:keygen/sp@128 -->

<!-- table:rtl-runs:keygen/min@128 -->
| DMEM | param | tier | accept | restart_b | restart_a2 |
|---|---|---|---:|---:|---:|
| 128 KiB | Ip | bngfaes | 3,557,153 | 3,557,191 | 3,557,179 |
| 128 KiB | Ip | bngfonly | 97,267,853 | 97,267,831 | 97,267,808 |
| 128 KiB | Ip | bnaesonly | 37,929,188 | - | - |
| 128 KiB | Ip | sw | 273,832,619 | - | - |
| 128 KiB | Is | bngfaes | 4,387,913 | 4,387,908 | 4,387,946 |
| 128 KiB | Is | bngfonly | 146,014,768 | 146,014,802 | 146,014,734 |
| 128 KiB | Is | bnaesonly | 36,667,714 | - | - |
| 128 KiB | Is | sw | 398,600,301 | - | - |
| 128 KiB | Ip3 | bngfaes | 6,804,005 | 6,803,975 | 6,803,965 |
| 128 KiB | Ip3 | bngfonly | 249,596,848 | 249,596,802 | 249,596,791 |
| 128 KiB | Ip3 | bnaesonly | 46,034,993 | - | - |
| 128 KiB | Ip3 | sw | 655,629,584 | - | - |

exec+wait in Ibex cycles of every timed run of each test; - where a test does not make that run.
Chip RTL under Verilator, 128 KiB DMEM profile, one loaded image per test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-runs:keygen/min@128 -->

<!-- table:rtl-runs:verify/full@128 -->
| DMEM | param | tier | accept | reject_resident | accept_resident |
|---|---|---|---:|---:|---:|
| 128 KiB | Ip | bngfaes | 156,362 | 156,305 | 156,305 |
| 128 KiB | Ip | bngfonly | 7,359,272 | 7,359,215 | 7,359,215 |
| 128 KiB | Ip | bnaesonly | 1,248,769 | 1,248,712 | 1,248,712 |
| 128 KiB | Ip | sw | 18,333,377 | 18,333,320 | 18,333,320 |
| 128 KiB | Is | bngfaes | 166,990 | 167,004 | 166,999 |
| 128 KiB | Is | bngfonly | 10,038,958 | 10,038,972 | 10,038,967 |
| 128 KiB | Is | bnaesonly | 878,929 | 878,942 | 878,943 |
| 128 KiB | Is | sw | 26,000,051 | 26,000,049 | 26,000,049 |
| 128 KiB | Ip3 | bngfaes | 196,359 | 196,369 | 196,369 |
| 128 KiB | Ip3 | bngfonly | 8,075,279 | 8,075,289 | 8,075,289 |
| 128 KiB | Ip3 | bnaesonly | 1,469,449 | 1,469,389 | 1,469,389 |
| 128 KiB | Ip3 | sw | 22,754,209 | 22,754,219 | 22,754,219 |

exec+wait in Ibex cycles of every timed run of each test; - where a test does not make that run.
Chip RTL under Verilator, 128 KiB DMEM profile, one loaded image per test. Measured 2026-11-15 to 2026-11-17 at `de52799642` (rtl-2026-11).
<!-- /table:rtl-runs:verify/full@128 -->

### Against the ISS

<!-- table:rtl-iss:all@128 -->
| DMEM | op | kernel | param | tier | ACC instructions | ISS cases with that count | exec+wait above the ISS cycles |
|---|---|---|---|---|---:|---|---:|
| 128 KiB | keygen | min | Ip | bngfaes | 2,924,593 | 0-11 | 543 |
| 128 KiB | keygen | min | Ip | bngfonly | 95,171,341 | 0-11 | 593 |
| 128 KiB | keygen | min | Ip | bnaesonly | 36,353,430 | 0-11 | 570 |
| 128 KiB | keygen | min | Ip | sw | 229,660,916 | 0-11 | 605 |
| 128 KiB | keygen | min | Is | bngfaes | 3,686,859 | 0-11 | 546 |
| 128 KiB | keygen | min | Is | bngfonly | 143,425,995 | 0-11 | 553 |
| 128 KiB | keygen | min | Is | bnaesonly | 34,041,272 | 0-11 | 539 |
| 128 KiB | keygen | min | Is | sw | 330,196,205 | 0-11 | 534 |
| 128 KiB | keygen | min | Ip3 | bngfaes | 6,161,233 | 0-11 | 585 |
| 128 KiB | keygen | min | Ip3 | bngfonly | 244,653,493 | 0-11 | 608 |
| 128 KiB | keygen | min | Ip3 | bnaesonly | 44,682,538 | 0-11 | 573 |
| 128 KiB | keygen | min | Ip3 | sw | 543,798,913 | 0-11 | 593 |
| 128 KiB | keygen | sp | Ip | bngfaes | 1,284,994 | 0-11 | 540 |
| 128 KiB | keygen | sp | Ip | bngfonly | 9,202,320 | 0-11 | 568 |
| 128 KiB | keygen | sp | Ip | bnaesonly | 33,579,442 | 0-11 | 554 |
| 128 KiB | keygen | sp | Ip | sw | 50,172,171 | 0-11 | 552 |
| 128 KiB | keygen | sp | Is | bngfaes | 1,795,872 | 0-11 | 572 |
| 128 KiB | keygen | sp | Is | bngfonly | 11,537,400 | 0-11 | 588 |
| 128 KiB | keygen | sp | Is | bnaesonly | 31,636,354 | 0-11 | 594 |
| 128 KiB | keygen | sp | Is | sw | 52,253,863 | 0-11 | 547 |
| 128 KiB | keygen | sp | Ip3 | bngfaes | 1,641,122 | 0-11 | 614 |
| 128 KiB | keygen | sp | Ip3 | bngfonly | 11,398,758 | 0-11 | 594 |
| 128 KiB | keygen | sp | Ip3 | bnaesonly | 39,346,543 | 0-11 | 587 |
| 128 KiB | keygen | sp | Ip3 | sw | 59,769,010 | 0-11 | 546 |
| 128 KiB | verify | full | Ip | bngfaes | 150,144 | 11 | 588 |
| 128 KiB | verify | full | Ip | bngfonly | 7,249,728 | 11 | 579 |
| 128 KiB | verify | full | Ip | bnaesonly | 1,208,825 | 11 | 569 |
| 128 KiB | verify | full | Ip | sw | 15,200,534 | 11 | 582 |
| 128 KiB | verify | full | Is | bngfaes | 164,308 | 11 | 543 |
| 128 KiB | verify | full | Is | bngfonly | 9,906,637 | 11 | 546 |
| 128 KiB | verify | full | Is | bnaesonly | 806,506 | 11 | 561 |
| 128 KiB | verify | full | Is | sw | 21,380,815 | 11 | 579 |
| 128 KiB | verify | full | Ip3 | bngfaes | 187,185 | 11 | 548 |
| 128 KiB | verify | full | Ip3 | bngfonly | 7,943,248 | 11 | 558 |
| 128 KiB | verify | full | Ip3 | bnaesonly | 1,410,102 | 11 | 577 |
| 128 KiB | verify | full | Ip3 | sw | 18,845,795 | 11 | 566 |

Instructions the ACC retired in each chip test, the cases whose ISS run of the same ELF retires exactly as many,
and how far the chip's exec+wait lies above the ISS cycles of the first such case (none: no case has that count).
Chip RTL under Verilator and the ISS, 128 KiB DMEM profile. Measured 2026-11-01 to 2026-11-17 at `7ca6de3b2e`, `de52799642` (iss-2026-10j, rtl-2026-11).
<!-- /table:rtl-iss:all@128 -->
