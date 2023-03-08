# SSKR for JavaCard

[![Build status](https://github.com/proxyco/jc-sskr/actions/workflows/gradle.yml/badge.svg)](https://github.com/proxyco/jc-sskr/actions/workflows/gradle.yml)

This is an implementation of [Sharded Secret Key Reconstruction (SSKR)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-011-sskr.md)
for JavaCard environments.

Gradle project contains one module:
- `applet`, the JavaCard applet can be used both for testing and building a `.cap` file

## Building

Run the `buildJavaCard` task:

```bash
./gradlew buildJavaCard
```

Generates a new cap file `./applet/build/javacard/com.proxy.sskr.cap`

Typical output:

```
[ant:convert] [ INFO: ] Converter [v3.1.0]
[ant:convert] [ INFO: ] Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
[ant:convert]
[ant:convert] [ INFO: ] conversion completed with 0 errors and 0 warnings.

[ant:cap] INFO: using JavaCard 3.1.0 SDK in ./libs-sdks/jc310r20210706_kit
[ant:cap] INFO: targeting JavaCard 3.0.4 SDK in ..libs-sdks.jc304_kit
[ant:cap] Building CAP with 1 applet from package com.proxy.sskr (AID: FFFFFF040506)
[ant:cap] com.proxy.sskr.Applet FFFFFF04050607
[ant:compile] Compiling files from ./applet/src/main/java
[ant:compile] Compiling 4 source files to /tmp/jccpro5411199499583907175
[ant:verify] Verification passed
[ant:cap] CAP saved to ./applet/build/javacard/com.proxy.sskr.cap
[ant:exp] EXP saved to ./applet/build/javacard/com.proxy.sskr.exp/com/proxy/sskr/javacard/sskr.exp
```

## Installation on a (physical) card

> **Warning**
> Make sure to set the correct ISD key in [`gradle.properties`](./gradle.properties).
> Attemping to authenticate with an incorrect key will increment the internal retry
> counter of most secure elements, and eventually lock the card permanently.
>
> ```
> # Replace with real key for distribution (use env variable or command line arg).
> issuerKey=40:41:42:43:44:45:46:47:48:49:4A:4B:4C:4D:4E:4F
> ```

> **Warning**
> This will delete any previous instances of the applet on your card.
> Make sure you are prepared to lose any persistent data they store.

```bash
./gradlew installJavaCard
```

To inspect already installed applets:

```bash
./gradlew listJavaCard
```

## Running tests

```
./gradlew test --rerun-tasks --info
```

Typical output:

```
tests.AppletTest > echo() STANDARD_OUT
    DEBUG | 2023-03-03 12:50:56 | [Test worker] cardTools.CardManager:307 | --> 800000000142 (6 B)
    DEBUG | 2023-03-03 12:50:56 | [Test worker] cardTools.Util:115 | --> [800000000142] (6 B)
    DEBUG | 2023-03-03 12:50:56 | [Test worker] cardTools.Util:122 | <-- 42 9000 (1 B)
    DEBUG | 2023-03-03 12:50:56 | [Test worker] cardTools.CardManager:315 | <-- 42 9000 (1) [0 ms]

tests.ShamirTest > roundtrip1() STANDARD_OUT
    secret: 0FF784DF000C4380A5ED683F7E6E3DCF
    0: 00112233445566778899AABBCCDDEEFF
    1: D43099FE444807C46921A4F33A2A798B
    2: D9AD4E3BEC2E1A7485698823ABF05D36
    3: 0D8CF5F6EC337BC764D1866B5D07CA42
    4: 1AA7FE3199BC5092EF3816B074CABDF2
    from 1: D43099FE444807C46921A4F33A2A798B
    from 2: D9AD4E3BEC2E1A7485698823ABF05D36
    from 4: 1AA7FE3199BC5092EF3816B074CABDF2
    recovered secret: 0FF784DF000C4380A5ED683F7E6E3DCF
    verified secret: true

tests.ShamirTest > roundtrip2() STANDARD_OUT
    secret: 204188BFA6B440A1BDFD6753FF55A8241E07AF5C5BE943DB917E3EFABC184B1A
    0: 2DCD14C2252DC8489AF3985030E74D5A48E8EFF1478AB86E65B43869BF39D556
    1: A1DFDD798388AADA635B9974472B4FC59A32AE520C42C9F6A0AF70149B882487
    2: 2EE99DAF727C0C7773B89A18DE64497FF7476DACD1015A45F482A893F7402CEF
    3: A2FB5414D4D96EE58A109B3CA9A84BE0259D2C0F9AC92BDD3199E0EED3F1DD3E
    4: 2B851D188B8F5B3653659CC0F7FA45102DADF04B708767385CD803862FCB3C3F
    5: A797D4A32D2A39A4AACD9DE48036478FFF77B1E83B4F16A099C34BFB0B7ACDEE
    6: 28A19475DCDE9F09BA2E9E881979413592027216E60C8513CDEE937C67B2C586
    from 3: A2FB5414D4D96EE58A109B3CA9A84BE0259D2C0F9AC92BDD3199E0EED3F1DD3E
    from 4: 2B851D188B8F5B3653659CC0F7FA45102DADF04B708767385CD803862FCB3C3F
    recovered secret: 204188BFA6B440A1BDFD6753FF55A8241E07AF5C5BE943DB917E3EFABC184B1A
    verified secret: true

tests.ShamirTest > recoverFromReference1() STANDARD_OUT
    recovered secret: 0FF784DF000C4380A5ED683F7E6E3DCF
    verified secret: true

tests.ShamirTest > recoverFromReference2() STANDARD_OUT
    recovered secret: 204188BFA6B440A1BDFD6753FF55A8241E07AF5C5BE943DB917E3EFABC184B1A
    verified secret: true

tests.SSKRTest > roundtrip() STANDARD_OUT
    secret: 7DAA851251002874E1A1995F0897E6B1
    0: 001111010091405D03C53896A1AB7FEA914B659E0F
    1: 00111101018F53CF68BDBFC092973B06D2AEE60559
    2: 0011110102AD6662D5352D3AC7D3F729179A78B3A3
    3: 001111120000112233445566778899AABBCCDDEEFF
    4: 0011111201FC2D359E6DC33A031129B9D0A95039A3
    5: 00111112022E3E180843AC4ABEB10F5B7E835040D3
    6: 0011111203D2020FA56A3A16CA28BF4815E6DD978F
    7: 0011111204450806B605A9587ABA37226670DAC5C1
    from 1 (0.1): 00111101018F53CF68BDBFC092973B06D2AEE60559
    from 2 (0.2): 0011110102AD6662D5352D3AC7D3F729179A78B3A3
    from 3 (1.0): 001111120000112233445566778899AABBCCDDEEFF
    from 5 (1.2): 00111112022E3E180843AC4ABEB10F5B7E835040D3
    from 6 (1.3): 0011111203D2020FA56A3A16CA28BF4815E6DD978F
    recovered secret: 7DAA851251002874E1A1995F0897E6B1
    verified secret: true

tests.SSKRTest > recoverFromReference1() STANDARD_OUT
    recovered secret: 7DAA851251002874E1A1995F0897E6B1
    verified secret: true

tests.SSKRTest > recoverWithPartialTransactions() STANDARD_OUT
    recovered secret: 7DAA851251002874E1A1995F0897E6B1
    verified secret: true

tests.SSKRTest > recoverWithTwoTransactions() STANDARD_OUT
    recovered secret: 7DAA851251002874E1A1995F0897E6B1
    verified secret: true

tests.SSKRTest > recoverWithDuplicates() STANDARD_OUT
    recovered secret: 7DAA851251002874E1A1995F0897E6B1
    verified secret: true

tests.SSKRTest > reset() STANDARD_OUT
    recovered secret: 7DAA851251002874E1A1995F0897E6B1
    verified secret: true

Finished generating test XML results (0.006 secs) into: ./applet/build/test-results/test
Finished generating test html results (0.009 secs) into: ./applet/build/reports/tests/test
```

## Performance

Average of three runs to generate a set of shares from a 128-bit secret.

| Group descriptors         | JCOP3 J3H145 | SLJ52WML140 |
| ------------------------- | -----------: | ----------: |
| 1 of (1,1)                |       125 ms |       42 ms |
| 1 of (2,3)                |       388 ms |      242 ms |
| 1 of (3,5)                |       818 ms |      608 ms |
| 2 of (2,3), (2,3), (2,3)  |      1440 ms |      860 ms |

## Origin, Authors, Copyright & Licenses

Unless otherwise noted (either in this [README.md](./README.md) or in the file's header comments)
the contents of this repository are Copyright © 2023 by Proxy, Inc, and are [licensed](./LICENSE)
under the [BSD-2-Clause Plus Patent License](https://spdx.org/licenses/BSD-2-Clause-Patent.html).

This table below also establishes provenance (repository of origin, permalink, and commit id) for
files included from repositories that are outside of this repository. Contributors to these files
are listed in the commit history for each repository, first with changes found in the commit
history of this repo, then in changes in the commit history of their repo of origin.

| File   | From   | Commit  | Authors & Copyright (c)  | License  |
| ------ | ------ | ------- | ------------------------ | -------- |
| GF256.java GF256Test.java | [codahale/shamir](https://github.com/codahale/shamir) | [codahale/shamir@f44e1ce](https://github.com/codahale/shamir/commit/f44e1cec1919103ad942252b42dcdf9630461c0a) | 2017 Coda Hale (coda.hale@gmail.com) | [Apache-2.0](https://spdx.org/licenses/Apache-2.0)

## Dependencies

Based on the [crocs-muni/javacard-gradle-template-edu](https://github.com/crocs-muni/javacard-gradle-template-edu) template, which uses:

- https://github.com/ph4r05/javacard-gradle-plugin
- https://github.com/martinpaljak/ant-javacard
- https://github.com/martinpaljak/oracle_javacard_sdks
- https://github.com/licel/jcardsim

## Supported Java versions

Java 8-u271 is the minimal version supported.

Make sure you have up to date java version (`-u` version) as older java 8 versions
have problems with recognizing some certificates as valid.

Only some Java versions are supported by the JavaCard SDKs.
Check the following compatibility table for more info:
https://github.com/martinpaljak/ant-javacard/wiki/Version-compatibility

