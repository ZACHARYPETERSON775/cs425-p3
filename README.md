# Project 3 - Subnetting and Forwarding

- Name: Zachary Peterson
- Email: ZACHARYPETESON775@u.boisestate.edu
- Class: CS425-001

## Known Bugs or Issues

There are no know bugs or issues at this time. All tests are passing and there are no leaks reported by `make leak` or `make leak-test`. IO and allocation errors are caught and reported rather than being left to crash.

## Experience

When I started this project I was confident that I could complete it without using AI; however, I quickly ran out of time due to projects from other classes and ended up heavily relying on AI.

I used the builtin AI provided with Github Codespaces and spend most of my time reviewing the code and reasoning provided to me by the AI. Through using AI, I discovered an alternative method for parsing strings using a cursor and how to better handle CLI input to my programs.

## Design

This project was designed and implimented using AI.

CIDR addresses are parsed in `cidr_parse()` which results in postfixs rangin from 0 to 32. The postfixes `/0`, `/31`, and `/32` are special cases. These cases affect `cidr_mask()`, `cidr_host_count()`, `cidr_first_host()`, and `cidr_last_host()`. `cidr_mask()` alwasy return an empty mask for `/0` and a full mask for `/32` or greater. `cidr_host_count()` returns 64-bit values to accompidate `/0` while detecting `/31` and `/32` and return their known host counts. `cidr_first_host()` and `cidr_last_host()` detect `/31` and `/32` and treat them as range exeptions.

`table_lookup()` scans every route in the table and checks whether is contains the desitination address using `cidr_contains()`. If a route matches, it keep if its prefix is the longest encounted. Previous matches with sorter prefixs are discarded so that results do not depend on insertion order.
