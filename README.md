# README

![Last release](https://img.shields.io/github/v/release/alterakey/ts2-disasm-ghidra)
![Last release date](https://img.shields.io/github/release-date-pre/alterakey/ts2-disasm-ghidra)
![Main branch deploy status](https://github.com/alterakey/ts2-disasm-ghidra/workflows/deploy/badge.svg)
![Main branch last commit](https://img.shields.io/github/last-commit/alterakey/ts2-disasm-ghidra/main)

ts2-disasm-ghidra is the native code disassmbling facility for trueseeing, powered by Ghidra.

## Installation

We provide containers so you can use right away as follows; to run:

    $ docker run --rm -v $(pwd):/out ghcr.io/alterakey/ts2-disasm-ghidra target.apk
    $ docker run --rm -v $(pwd):/out ghcr.io/alterakey/ts2-disasm-ghidra target.xapk
    $ docker run --rm -v $(pwd):/out ghcr.io/alterakey/ts2-disasm-ghidra target.ipa
