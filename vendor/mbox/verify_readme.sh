#!/usr/bin/env bash
diff -u <( fgrep -v '[![' README.md ) <( fgrep '//!' src/lib.rs | cut -c 5- )
