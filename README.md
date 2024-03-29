# LIBE2

One library to ~rule~ serve them all.

## Table of contents
* [Introduction](#introduction)
* [Project folders structure](#project-folders-structure)
* [Installation guide](#installation-guide)
  * [Compiling code](#compiling-code)
* [Creation of Asn1](#creation-of-asn1)

## Introduction
This repo contains code that is generated from ASN1 descriptions
as well as CMake bits that allow it to be used as a submodule
to other projects.

## Project folder structure

```
├── src
│   ├── e2ap        // E2AP message structure
│   │   └── wrapper     // E2AP message encoding and decoding
│   └── e2sm        // E2SM message structure
│       └── wrapper     // E2SM message encoding and decoding
```

## Installation guide

### Compiling code

Use cmake and then make to build code from project root.

```
$ cmake .
+++ riclibe2ap library install target directory: lib
+++ mmp version from tag: '1;0;0'
+++ pkg name: riclibe2ap-rotten_1.0.0_amd64.deb
### make package will generate only deb package; cannot find support to generate rpm packages
+++ profiling is off
-- Configuring done
-- Generating done
-- Build files have been written to: <path>/libe2ap
```

Use make to generate shared library (.so).

```
$ sudo make 
```

Use make to install shared library (.so).

```
$ sudo make install
```

## Creation of ASN1C

I started from [ns-o-ran-xapp-rc](https://github.com/wineslab/ns-o-ran-xapp-rc), which included the E2SM `e-release` control.
Subsequentely, I have included merge the [ns-o-ran-scp-ric-app-kpimon](https://github.com/wineslab/ns-o-ran-scp-ric-app-kpimon) which are still at `e-release`.
Finally, I used the ASN1 from [`ns-o-ran` e2sim](https://github.com/wineslab/oran-e2sim).
