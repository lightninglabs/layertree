Witness data for the sparse profile is measured on a 6-leaf tree (compressed proofs);
add 41 bytes per additional non-empty sibling (about log2 N in total); the S/65536 row is the measured exit of a member of a 2^16-leaf tree.

| profile | D | transition | script (B) | witness data (B) | control block (B) | total witness (WU) | varops used | sigops |
|---|---|---|---|---|---|---|---|---|
| D | 8 | EXIT_1 (owner) | 1397 | 574 | 129 | 2100 | 2330849 | 1 |
| D | 8 | EXIT_1 (evict) | 1397 | 575 | 129 | 2101 | 2331244 | 1 |
| D | 8 | JOIN_2 | 1137 | 415 | 129 | 1681 | 2280970 | 1 |
| D | 8 | JOIN_0 | 1313 | 498 | 129 | 1940 | 2319452 | 1 |
| D | 8 | JOINK_2 | 2137 | 869 | 129 | 3135 | 2473473 | 1 |
| D | 8 | UPDATE | 1433 | 752 | 129 | 2314 | 2839671 | 2 |
| D | 8 | CLAIM | 2469 | 1026 | 129 | 3624 | 2528447 | 1 |
| D | 8 | EXIT_2 | 2339 | 1085 | 129 | 3553 | 2996728 | 2 |
| D | 8 | EXIT_1 (terminal) | 1397 | 0 | 129 | 1526 | 1498287 | 1 |
| D | 12 | EXIT_1 (owner) | 1749 | 738 | 129 | 2616 | 2407765 | 1 |
| D | 12 | EXIT_1 (evict) | 1749 | 739 | 129 | 2617 | 2408160 | 1 |
| D | 12 | JOIN_2 | 1489 | 579 | 129 | 2197 | 2357886 | 1 |
| D | 12 | JOIN_0 | 1665 | 662 | 129 | 2456 | 2396380 | 1 |
| D | 12 | JOINK_2 | 2841 | 1197 | 129 | 4167 | 2627329 | 1 |
| D | 12 | UPDATE | 1785 | 916 | 129 | 2830 | 2916599 | 2 |
| D | 12 | CLAIM | 3173 | 1358 | 129 | 4660 | 2682315 | 1 |
| D | 12 | EXIT_2 | 3043 | 1413 | 129 | 4585 | 3150584 | 2 |
| D | 12 | EXIT_1 (terminal) | 1749 | 0 | 129 | 1878 | 1575179 | 1 |
| D | 16 | EXIT_1 (owner) | 2101 | 902 | 129 | 3132 | 2484681 | 1 |
| D | 16 | EXIT_1 (evict) | 2101 | 903 | 129 | 3133 | 2485076 | 1 |
| D | 16 | JOIN_2 | 1841 | 743 | 129 | 2713 | 2434802 | 1 |
| D | 16 | JOIN_0 | 2017 | 826 | 129 | 2972 | 2473308 | 1 |
| D | 16 | JOINK_2 | 3545 | 1525 | 129 | 5199 | 2781185 | 1 |
| D | 16 | UPDATE | 2137 | 1080 | 129 | 3346 | 2993527 | 2 |
| D | 16 | CLAIM | 3877 | 1690 | 129 | 5696 | 2836183 | 1 |
| D | 16 | EXIT_2 | 3747 | 1741 | 129 | 5617 | 3304440 | 2 |
| D | 16 | EXIT_1 (terminal) | 2101 | 0 | 129 | 2230 | 1652071 | 1 |
| D | 20 | EXIT_1 (owner) | 2453 | 1066 | 129 | 3648 | 2561597 | 1 |
| D | 20 | EXIT_1 (evict) | 2453 | 1067 | 129 | 3649 | 2561992 | 1 |
| D | 20 | JOIN_2 | 2193 | 907 | 129 | 3229 | 2511718 | 1 |
| D | 20 | JOIN_0 | 2369 | 990 | 129 | 3488 | 2550236 | 1 |
| D | 20 | JOINK_2 | 4249 | 1853 | 129 | 6231 | 2935041 | 1 |
| D | 20 | UPDATE | 2489 | 1244 | 129 | 3862 | 3070455 | 2 |
| D | 20 | CLAIM | 4581 | 2022 | 129 | 6732 | 2990051 | 1 |
| D | 20 | EXIT_2 | 4451 | 2069 | 129 | 6649 | 3458296 | 2 |
| D | 20 | EXIT_1 (terminal) | 2453 | 0 | 129 | 2582 | 1728963 | 1 |
| S | 32 | EXIT_1 (owner) | 5147 | 326 | 129 | 5602 | 3074978 | 1 |
| S | 32 | EXIT_1 (evict) | 5147 | 327 | 129 | 5603 | 3075373 | 1 |
| S | 32 | JOIN_0 | 5131 | 367 | 129 | 5627 | 3073100 | 1 |
| S | 32 | JOINK_2 | 9773 | 606 | 129 | 10508 | 3980769 | 1 |
| S | 32 | UPDATE | 5347 | 547 | 129 | 6023 | 3596390 | 2 |
| S | 32 | CLAIM | 9971 | 688 | 129 | 10788 | 4016373 | 1 |
| S | 32 | EXIT_2 | 9839 | 630 | 129 | 10598 | 4484660 | 2 |
| S | 32 | EXIT_1 (terminal) | 5147 | 0 | 129 | 5276 | 2242843 | 1 |
| S | 64 | EXIT_1 (owner) | 9499 | 326 | 129 | 9954 | 3966661 | 1 |
| S | 64 | EXIT_1 (evict) | 9499 | 327 | 129 | 9955 | 3967056 | 1 |
| S | 64 | JOIN_0 | 9483 | 326 | 129 | 9938 | 3964827 | 1 |
| S | 64 | JOINK_2 | 18477 | 606 | 129 | 19212 | 5763919 | 1 |
| S | 64 | UPDATE | 9699 | 547 | 129 | 10375 | 4488244 | 2 |
| S | 64 | CLAIM | 18675 | 647 | 129 | 19451 | 5800098 | 1 |
| S | 64 | EXIT_2 | 18543 | 671 | 129 | 19343 | 6267721 | 2 |
| S | 64 | EXIT_1 (terminal) | 9499 | 0 | 129 | 9628 | 3134508 | 1 |
| S | 256 | EXIT_1 (owner) | 35611 | 285 | 129 | 36025 | 9296589 | 1 |
| S | 256 | EXIT_1 (evict) | 35611 | 286 | 129 | 36026 | 9296984 | 1 |
| S | 256 | JOIN_0 | 35595 | 367 | 129 | 36091 | 9293755 | 1 |
| S | 256 | JOINK_2 | 70701 | 688 | 129 | 71518 | 16421829 | 1 |
| S | 256 | UPDATE | 35811 | 588 | 129 | 36528 | 9818912 | 2 |
| S | 256 | CLAIM | 70899 | 688 | 129 | 71716 | 16460515 | 1 |
| S | 256 | EXIT_2 | 70767 | 548 | 129 | 71444 | 16927207 | 2 |
| S | 256 | EXIT_1 (terminal) | 35611 | 0 | 129 | 35740 | 8464248 | 1 |
| D | 16 | UPDATE_X | 2144 | 1144 | 129 | 3417 | 3494028 | 3 |
| S | 32 | UPDATE_X | 5354 | 611 | 129 | 6094 | 4096882 | 3 |
| D | 16 | CLAIM_H | 3885 | 1722 | 129 | 5736 | 2840303 | 1 |
| S | 32 | CLAIM_H | 9979 | 515 | 129 | 10623 | 4021511 | 1 |
| D | 16 | SPLIT | 3765 | 1674 | 129 | 5568 | 2816654 | 1 |
| S | 32 | SPLIT | 9859 | 483 | 129 | 10471 | 3997985 | 1 |
| D | 16 | CLAIM_X | 3884 | 1754 | 129 | 5767 | 3336633 | 2 |
| D | 16 | CLAIM_HX | 3892 | 1786 | 129 | 5807 | 3340795 | 2 |
| S | 32 | CLAIM_X | 9978 | 547 | 129 | 10654 | 4517904 | 2 |
| S | 32 | CLAIM_HX | 9986 | 579 | 129 | 10694 | 4522066 | 2 |
| D | 16 | EXIT_1_TOWER | 2207 | 902 | 129 | 3238 | 2496617 | 1 |
| S | 32 | EXIT_1_TOWER | 5253 | 326 | 129 | 5708 | 3086914 | 1 |
| S/bitmap | 32 | EXIT_1 (owner) | 5423 | 330 | 129 | 5882 | 3080946 | 1 |
| S/bitmap | 32 | JOIN_0 | 5407 | 371 | 129 | 5907 | 3079436 | 1 |
| S/bitmap | 64 | EXIT_1 (owner) | 10063 | 334 | 129 | 10526 | 3979013 | 1 |
| S/bitmap | 64 | JOIN_0 | 10047 | 334 | 129 | 10510 | 3977179 | 1 |
| S/65536 | 32 | EXIT_1 (owner) | 5147 | 900 | 129 | 6176 | 3072262 | 1 |
| D/minimal | 8 | EXIT_1 (owner) | 1538 | 566 | 129 | 2233 | 2696051 | 1 |
| D/minimal | 16 | EXIT_1 (owner) | 2378 | 886 | 129 | 3393 | 2855147 | 1 |
| D/subtree | 16 | EVICT_SUBTREE_2 (4 positions) | 2709 | 1051 | 129 | 3889 | 2498069 | 1 |
| D | 16 | EXIT_4 (evictions, for comparison) | 7039 | - | 129 | - | - | 4 |
| D/subtree | 16 | EVICT_SUBTREE_4 (16 positions) | 5281 | 2129 | 129 | 7539 | 2689863 | 1 |
| D | 16 | EXIT_16 (evictions, for comparison) | 26791 | - | 129 | - | - | 16 |
| D/subtree | 16 | EVICT_SUBTREE_6 (64 positions) | 16097 | 6455 | 129 | 22681 | 3552831 | 1 |
| D | 16 | EXIT_64 (evictions, for comparison) | 105847 | - | 129 | - | - | 64 |
| D/subtree | 20 | EVICT_SUBTREE_8 (256 positions) | 60242 | 24401 | 129 | 84772 | 7239651 | 1 |
| D | 20 | EXIT_256 (evictions, for comparison) | 512184 | - | 129 | - | - | 256 |
| D/subtree | 16 | REWRITE_2 (4 positions, mixed) | 2843 | 1528 | 129 | 4500 | 3578674 | 3 |
| D/subtree | 16 | REWRITE_4 (16 positions, mixed) | 5784 | 4099 | 129 | 10012 | 7527477 | 10 |
| D/subtree | 16 | REWRITE_6 (64 positions, mixed) | 18236 | 14104 | 129 | 32469 | 22942248 | 37 |
| D/subtree | 16 | REWRITE_X_4 (16 positions, mixed) | 6082 | 4675 | 129 | 10886 | 12037089 | 19 |
| D/subtree | 16 | REWRITE_4 (16 positions, top-up) | 5784 | 4333 | 129 | 10246 | 3093885 | 1 |
| D/subtree | 16 | REWRITE_4 (16 positions, top-up, amount-only elements) | 5784 | 2605 | 129 | 8518 | 3110461 | 1 |
| D/subtree | 16 | REWRITE_6 (64 positions, top-up) | 18236 | 15387 | 129 | 33752 | 5227781 | 1 |
| D/subtree | 16 | REWRITE_6 (64 positions, top-up, amount-only elements) | 18236 | 8475 | 129 | 26840 | 5294085 | 1 |
| D/subtree | 16 | DETACH_8 | 1548 | 497 | 129 | 2174 | 3152083 | 1 |
| MID/D | 16 | EXIT_1 (owner) | 3367 | 978 | 129 | 4474 | n/a (0xC0) | 1 |
| MID/D | 16 | EXIT_1 (evict) | 3367 | 979 | 129 | 4475 | n/a (0xC0) | 1 |
| MID/D | 16 | JOIN_2 | 2884 | 794 | 129 | 3807 | n/a (0xC0) | 1 |
| MID/D | 16 | JOINK_2 | 5885 | 1637 | 129 | 7651 | n/a (0xC0) | 1 |
| MID/D | 16 | UPDATE | 3479 | 1156 | 129 | 4764 | n/a (0xC0) | 2 |
| MID/D | 16 | CLAIM | 6526 | 1840 | 129 | 8495 | n/a (0xC0) | 1 |
| MID/S | 31 | EXIT_1 (owner) | 9402 | 796 | 129 | 10327 | n/a (0xC0) | 1 |
| MID/S | 31 | EXIT_1 (evict) | 9402 | 797 | 129 | 10328 | n/a (0xC0) | 1 |
| MID/S | 31 | JOIN_0 | 9382 | 783 | 129 | 10294 | n/a (0xC0) | 1 |
| MID/S | 31 | JOINK_2 | 18241 | 1433 | 129 | 19803 | n/a (0xC0) | 1 |
| MID/S | 31 | UPDATE | 9525 | 1002 | 129 | 10656 | n/a (0xC0) | 2 |
| MID/S | 31 | CLAIM | 18596 | 1551 | 129 | 20276 | n/a (0xC0) | 1 |
| MID/D | 16 | UPDATE_X | 3483 | 1225 | 129 | 4837 | n/a (0xC0) | 3 |
| MID/S | 31 | UPDATE_X | 9529 | 1032 | 129 | 10690 | n/a (0xC0) | 3 |
| MID/D | 16 | CLAIM_H | 6534 | 1869 | 129 | 8532 | n/a (0xC0) | 1 |
| MID/S | 31 | CLAIM_H | 18604 | 1446 | 129 | 20179 | n/a (0xC0) | 1 |
| MID/D | 16 | SPLIT | 6371 | 1821 | 129 | 8321 | n/a (0xC0) | 1 |
| MID/S | 31 | SPLIT | 18441 | 1420 | 129 | 19990 | n/a (0xC0) | 1 |
| MID/D | 16 | CLAIM_X | 6530 | 1901 | 129 | 8560 | n/a (0xC0) | 2 |
| MID/D | 16 | CLAIM_HX | 6538 | 1933 | 129 | 8600 | n/a (0xC0) | 2 |
| MID/S | 31 | CLAIM_X | 18600 | 1483 | 129 | 20212 | n/a (0xC0) | 2 |
| MID/S | 31 | CLAIM_HX | 18608 | 1515 | 129 | 20252 | n/a (0xC0) | 2 |
| MID/D | 16 | EXIT_1_TOWER | 3488 | 978 | 129 | 4595 | n/a (0xC0) | 1 |
| MID/S | 31 | EXIT_1_TOWER | 9523 | 796 | 129 | 10448 | n/a (0xC0) | 1 |
| MID/D | 16 | DETACH_8 | 2174 | 534 | 129 | 2837 | n/a (0xC0) | 1 |
| MID/D | 16 | EVICT_SUBTREE_2 (4 positions, every fifth exited) | 4169 | 1157 | 129 | 5455 | n/a (0xC0) | 1 |
| MID/D | 16 | EVICT_SUBTREE_4 (16 positions, every fifth exited) | 7977 | 2417 | 129 | 10523 | n/a (0xC0) | 1 |
| MID/D | 16 | EVICT_SUBTREE_6 (64 positions, every fifth exited) | 24169 | 7461 | 129 | 31759 | n/a (0xC0) | 1 |
| MID/D | 16 | EVICT_SUBTREE_5 (32 positions, all occupied) | 13321 | 4907 | 129 | 18357 | n/a (0xC0) | 1 |
| MID/D | 16 | REWRITE_2 (4 positions, mixed) | 5047 | 1642 | 129 | 6818 | n/a (0xC0) | 3 |
| MID/D | 16 | REWRITE_4 (16 positions, mixed) | 11556 | 4436 | 129 | 16121 | n/a (0xC0) | 10 |
| MID/D | 16 | REWRITE_X_4 (16 positions, mixed) | 11716 | 5012 | 129 | 16857 | n/a (0xC0) | 19 |
| MID/D | 16 | REWRITE_5 (32 positions, update) | 20522 | 10787 | 129 | 31438 | n/a (0xC0) | 33 |
| MID/D | 16 | REWRITE_5 (32 positions, exit) | 20522 | 6851 | 129 | 27502 | n/a (0xC0) | 33 |
| MID/D | 16 | REWRITE_5 (32 positions, top-up) | 20522 | 8739 | 129 | 29390 | n/a (0xC0) | 1 |
| MID/D | 16 | REWRITE_5 (32 positions, top-up, amount-only slots) | 20522 | 5027 | 129 | 25678 | n/a (0xC0) | 1 |
| MIN/D | 16 | EXIT_1 (owner) | 3640 | 1175 | 129 | 4944 | n/a (0xC0) | 2 |
| MIN/D | 16 | SPLIT | 6655 | 2018 | 129 | 8802 | n/a (0xC0) | 2 |
| CCV/D | 16 | EXIT_1 (owner) | 1716 | 838 | 129 | 2683 | 2319297 | 1 |
| CCV/D | 16 | EXIT_1 (evict) | 1716 | 839 | 129 | 2684 | 2319708 | 1 |
| CCV/D | 16 | EXIT_1 (terminal) | 1716 | 837 | 129 | 2682 | 1819116 | 1 |
| CCV/D | 16 | JOIN_2 | 1456 | 679 | 129 | 2264 | 1769620 | 1 |
| CCV/D | 16 | JOINK_2 | 3160 | 1461 | 129 | 4750 | 2116003 | 1 |
| CCV/D | 16 | UPDATE | 1760 | 1016 | 129 | 2905 | 2328505 | 2 |
| CCV/D | 16 | EXIT_2 | 3362 | 1677 | 129 | 5168 | 3638843 | 2 |
| CCV/D | 16 | EVICT_SUBTREE_1 | 1962 | 681 | 129 | 2772 | 1797718 | 1 |
| CCV/D | 16 | UPDATE_X | 1767 | 1080 | 129 | 2976 | 2829006 | 3 |
| CCV/D | 16 | SPLIT | 3378 | 1610 | 129 | 5117 | 2151472 | 1 |
| CCV/S | 32 | EXIT_1 (owner) | 4762 | 262 | 129 | 5153 | 2909594 | 1 |
| CCV/S | 32 | EXIT_1 (evict) | 4762 | 263 | 129 | 5154 | 2910005 | 1 |
| CCV/S | 32 | EXIT_1 (terminal) | 4762 | 180 | 129 | 5071 | 2409888 | 1 |
| CCV/S | 32 | JOIN_0 | 4746 | 303 | 129 | 5178 | 2407918 | 1 |
| CCV/S | 32 | JOINK_2 | 9388 | 542 | 129 | 10059 | 3315587 | 1 |
| CCV/S | 32 | UPDATE | 4970 | 483 | 129 | 5582 | 2931368 | 2 |
| CCV/S | 32 | EXIT_2 | 9454 | 566 | 129 | 10149 | 4819006 | 2 |
| CCV/S | 32 | UPDATE_X | 4977 | 547 | 129 | 5653 | 3431860 | 3 |
| CCV/S | 32 | SPLIT | 9472 | 419 | 129 | 10020 | 3332803 | 1 |
| CCV-c0/D | 16 | EXIT_1 (owner, c0) | 3002 | 914 | 129 | 4045 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | EXIT_1 (evict, c0) | 3002 | 915 | 129 | 4046 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | EXIT_1 (terminal, c0) | 3002 | 904 | 129 | 4035 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | JOIN_2 (c0) | 2516 | 730 | 129 | 3375 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | UPDATE (c0) | 3119 | 1092 | 129 | 4340 | n/a (0xC0) | 2 |
| CCV-c0/D | 16 | UPDATE_X (c0) | 3123 | 1156 | 129 | 4408 | n/a (0xC0) | 3 |
| CCV-c0/D | 16 | EXIT_2 (c0) | 5883 | 1824 | 129 | 7836 | n/a (0xC0) | 2 |
| CCV-c0/S | 31 | EXIT_1 (owner, c0) | 9037 | 732 | 129 | 9898 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | EXIT_1 (evict, c0) | 9037 | 733 | 129 | 9899 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | EXIT_1 (terminal, c0) | 9037 | 656 | 129 | 9822 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | JOIN_0 (c0) | 9014 | 719 | 129 | 9862 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | UPDATE (c0) | 9165 | 905 | 129 | 10199 | n/a (0xC0) | 2 |
| CCV-c0/S | 31 | UPDATE_X (c0) | 9169 | 969 | 129 | 10267 | n/a (0xC0) | 3 |
| CCV-c0/S | 31 | EXIT_2 (c0) | 17953 | 1443 | 129 | 19525 | n/a (0xC0) | 2 |
| CCV/D | 16 | EVICT_SUBTREE_2 (4 positions, every fifth exited) | 2340 | 987 | 129 | 3456 | 3332386 | 1 |
| CCV/D | 16 | EVICT_SUBTREE_4 (16 positions, every fifth exited) | 4960 | 2065 | 129 | 7154 | 8522510 | 1 |
| CCV/D | 16 | EVICT_SUBTREE_6 (64 positions, every fifth exited) | 15968 | 6391 | 129 | 22488 | 28379132 | 1 |
| CCV-c0/D | 16 | EVICT_SUBTREE_2 (4 positions, every fifth exited) | 3817 | 1093 | 129 | 5039 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | EVICT_SUBTREE_4 (16 positions, every fifth exited) | 7673 | 2353 | 129 | 10155 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | EVICT_SUBTREE_6 (64 positions, every fifth exited) | 24057 | 7397 | 129 | 31583 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | SPLIT | 6001 | 1757 | 129 | 7887 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | SPLIT | 18071 | 1356 | 129 | 19556 | n/a (0xC0) | 1 |
| CCV/D | 16 | CLAIM | 3490 | 1626 | 129 | 5245 | 2170959 | 1 |
| CCV/D | 16 | CLAIM_H | 3498 | 1658 | 129 | 5285 | 2175121 | 1 |
| CCV/S | 32 | CLAIM | 9584 | 419 | 129 | 10132 | 3352194 | 1 |
| CCV/S | 32 | CLAIM_H | 9592 | 451 | 129 | 10172 | 3356356 | 1 |
| CCV-c0/D | 16 | CLAIM | 6156 | 1773 | 129 | 8058 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | CLAIM_H | 6164 | 1805 | 129 | 8098 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | CLAIM | 18226 | 1350 | 129 | 19705 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | CLAIM_H | 18234 | 1382 | 129 | 19745 | n/a (0xC0) | 1 |
| CCV/D | 16 | CLAIM_X | 3497 | 1690 | 129 | 5316 | 2671451 | 2 |
| CCV/D | 16 | CLAIM_HX | 3505 | 1722 | 129 | 5356 | 2675613 | 2 |
| CCV/S | 32 | CLAIM_X | 9591 | 483 | 129 | 10203 | 3852722 | 2 |
| CCV/S | 32 | CLAIM_HX | 9599 | 515 | 129 | 10243 | 3856884 | 2 |
| CCV-c0/D | 16 | CLAIM_X | 6160 | 1837 | 129 | 8126 | n/a (0xC0) | 2 |
| CCV-c0/D | 16 | CLAIM_HX | 6168 | 1869 | 129 | 8166 | n/a (0xC0) | 2 |
| CCV-c0/S | 31 | CLAIM_X | 18230 | 1419 | 129 | 19778 | n/a (0xC0) | 2 |
| CCV-c0/S | 31 | CLAIM_HX | 18238 | 1451 | 129 | 19818 | n/a (0xC0) | 2 |
| CCV/D | 16 | DETACH_8 | 973 | 433 | 129 | 1535 | 2154472 | 1 |
| CCV-c0/D | 16 | DETACH_8 | 1628 | 470 | 129 | 2227 | n/a (0xC0) | 1 |
| CCV/D | 16 | REWRITE_2 (4 positions, mixed) | 2482 | 1464 | 129 | 4075 | 3413485 | 3 |
| CCV/D | 16 | REWRITE_4 (16 positions, mixed) | 5471 | 4035 | 129 | 9635 | 7862121 | 10 |
| CCV/D | 16 | REWRITE_X_4 (16 positions, mixed) | 5769 | 4611 | 129 | 10509 | 12371733 | 19 |
| CCV/D | 16 | REWRITE_6 (64 positions, mixed) | 18115 | 14040 | 129 | 32284 | 26775723 | 37 |
| CCV/D | 16 | REWRITE_6 (64 positions, update) | 18115 | 19419 | 129 | 37663 | 36573255 | 65 |
| CCV/D | 16 | REWRITE_6 (64 positions, exit) | 18115 | 11995 | 129 | 30239 | 67828173 | 65 |
| CCV-c0/D | 16 | REWRITE_2 (4 positions, mixed) | 4703 | 1578 | 129 | 6410 | n/a (0xC0) | 3 |
| CCV-c0/D | 16 | REWRITE_4 (16 positions, mixed) | 11260 | 4372 | 129 | 15761 | n/a (0xC0) | 10 |
| CCV-c0/D | 16 | REWRITE_X_4 (16 positions, mixed) | 11420 | 4948 | 129 | 16497 | n/a (0xC0) | 19 |
| CCV-c0/D | 16 | REWRITE_5 (32 positions, update) | 20290 | 10723 | 129 | 31142 | n/a (0xC0) | 33 |
| CCV-c0/D | 16 | REWRITE_5 (32 positions, exit) | 20290 | 6787 | 129 | 27206 | n/a (0xC0) | 33 |
| CCV/D | 16 | REWRITE_6 (64 positions, top-up) | 18115 | 15323 | 129 | 33567 | 4562759 | 1 |
| CCV/D | 16 | REWRITE_6 (64 positions, top-up, amount-only elements) | 18115 | 8411 | 129 | 26655 | 4629063 | 1 |
| CCV-c0/D | 16 | REWRITE_5 (32 positions, top-up) | 20290 | 8675 | 129 | 29094 | n/a (0xC0) | 1 |
| CCV-c0/D | 16 | REWRITE_5 (32 positions, top-up, amount-only elements) | 20290 | 4963 | 129 | 25382 | n/a (0xC0) | 1 |
| CCV/D | 16 | EXIT_1_TOWER | 1826 | 838 | 129 | 2793 | 2331249 | 1 |
| CCV/S | 32 | EXIT_1_TOWER | 4872 | 262 | 129 | 5263 | 2921546 | 1 |
| CCV-c0/D | 16 | EXIT_1_TOWER | 3123 | 914 | 129 | 4166 | n/a (0xC0) | 1 |
| CCV-c0/S | 31 | EXIT_1_TOWER | 9158 | 732 | 129 | 10019 | n/a (0xC0) | 1 |
