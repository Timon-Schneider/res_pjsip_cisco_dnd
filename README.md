# res_pjsip_cisco_dnd

An Asterisk PJSIP module that makes the **DND (Do Not Disturb) softkey** on Cisco CP-8xxx IP phones work seamlessly with FreePBX / Asterisk 21.

---

## The problem

When a user presses the DND softkey, Cisco CP-8xxx phones send a `PUBLISH` request carrying a `application/pidf+xml` body with proprietary Cisco activity markers:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<presence ...>
  <tuple id="1">
    <status>
      <basic>open</basic>
      <!-- Cisco proprietary DND state -->
      <ce:dnd xmlns:ce="urn:cisco:params:xml:ns:pidf:ext"/>
    </status>
  </tuple>
</presence>
```

By default, Asterisk's standard presence modules don't translate this into FreePBX's internal DND state (`AstDB DND/<ext>`).
Furthermore, Cisco phones often send these out-of-dialog `PUBLISH` requests using their MAC address as the SIP `From` user. Asterisk's normal PJSIP distributor will challenge this with a `401 Unauthorized`. Since the phone's provisioned credentials often don't match the MAC-based endpoint name exactly in real deployments, the phone goes into an infinite retry loop and eventually locks up.

This module intercepts these specific `PUBLISH` messages at the transport layer (before the PJSIP distributor performs endpoint identification or digest auth), applies the DND state directly to Asterisk's internal database (AstDB) simulating FreePBX's `*78` / `*79` feature codes, updates the device state for BLF compatibility, and immediately returns a `200 OK` with a spoofed `SIP-ETag` to satisfy the phone.

---

## Requirements

| Component | Version tested |
|---|---|
| OS | Debian / Ubuntu (FreePBX 17 ISO) |
| FreePBX | 17 |
| Asterisk | 21.5.0 |
| Asterisk source (headers only) | 21.12.2 |
| GCC | 12+ (system default) |
| Cisco phones | CP-8811 |

---

## Installation

### Step 1 — Install build tools

```bash
apt-get update
apt-get install -y gcc make wget tar \
    libssl-dev libncurses5-dev uuid-dev \
    libjansson-dev libxml2-dev libsqlite3-dev \
    libedit-dev binutils
```

### Step 2 — Download the Asterisk source tree

The source tree is needed **for headers only** — you do not recompile Asterisk.
Use the closest available version to what FreePBX installed (21.12.2 works fine with 21.5.0):

```bash
cd /usr/src
wget https://downloads.asterisk.org/pub/telephony/asterisk/asterisk-21.12.2.tar.gz
tar xzf asterisk-21.12.2.tar.gz
```

Run `./configure` to generate `autoconfig.h` and unpack the bundled pjproject headers:

```bash
cd /usr/src/asterisk-21.12.2
./configure --with-pjproject-bundled
```

> You do **not** need to run `make`.

### Step 3 — Create `buildopts.h`

Asterisk enforces a build-option checksum between a module and the running binary.
Extract the checksum from the already-installed `res_pjsip.so`:

Write the header:

```bash
BUILDSUM=$(strings /usr/lib/x86_64-linux-gnu/asterisk/modules/res_pjsip.so \
    | grep -E "^[a-f0-9]{32}$" | head -1)
echo "Found checksum: $BUILDSUM"

cat > /usr/src/asterisk-21.12.2/include/asterisk/buildopts.h <<EOF
#ifndef _ASTERISK_BUILDOPTS_H
#define _ASTERISK_BUILDOPTS_H

#if defined(HAVE_COMPILER_ATTRIBUTE_WEAKREF)
#define __ref_undefined __attribute__((weakref));
#else
#define __ref_undefined ;
#endif

#define AST_BUILDOPT_SUM "${BUILDSUM}"

#endif /* _ASTERISK_BUILDOPTS_H */
EOF
```

### Step 4 — Copy the source file

Copy or create the `res_pjsip_cisco_dnd.c` file into the Asterisk source directory:

```bash
cp res_pjsip_cisco_dnd.c /usr/src/asterisk-21.12.2/res/
```

### Step 5 — Compile

```bash
ASTSRC=/usr/src/asterisk-21.12.2
MODDIR=/usr/lib/x86_64-linux-gnu/asterisk/modules
PJROOT=${ASTSRC}/third-party/pjproject/source

gcc -fPIC -shared -g -O2 \
  -DASTERISK_REGISTER_FILE \
  -D_GNU_SOURCE \
  -DAST_MODULE_SELF_SYM=__local_ast_module_self \
  -DAST_MODULE=\"res_pjsip_cisco_dnd\" \
  -I${ASTSRC}/include \
  -I${PJROOT}/pjsip/include \
  -I${PJROOT}/pjlib/include \
  -I${PJROOT}/pjlib-util/include \
  -I${PJROOT}/pjmedia/include \
  -I${PJROOT}/pjnath/include \
  -o ${MODDIR}/res_pjsip_cisco_dnd.so \
  ${ASTSRC}/res/res_pjsip_cisco_dnd.c \
  && echo "COMPILE OK"
```

A successful build prints `COMPILE OK` and may produce a few harmless warnings. No errors.

### Step 6 — Load the module

```bash
asterisk -rx "module load res_pjsip_cisco_dnd.so"
asterisk -rx "module show like cisco"
```

Expected output:

```
Module                             Description                              Use Count  Status      Support Level
res_pjsip_cisco_dnd.so             Cisco x-cisco-remotecc DND Handler       0          Running     extended
```

FreePBX auto-loads this automatically on future restarts via `modules.conf`.

---

## Configuration & Extension Resolution

When a Cisco phone sends a `PUBLISH`, it often uses its MAC address as the URI (e.g., `sip:cc5a535fc4b7@pbx`). This module attempts to resolve the actual extension number in the following order:

1.  **Operator Override via `set_var` (Recommended):**
    If the module cannot figure out the extension from the SIP headers, or you want to explicitly pin it, you can define a variable in FreePBX.
    Add the following to `/etc/asterisk/pjsip.endpoint_custom_post.conf`:
    ```ini
    [your_endpoint_name](+)
    set_var = CISCO_DND_EXTEN=200
    ```
    Then reload pjsip: `asterisk -rx "pjsip reload"`

2.  **Contact Header:** Checks the `Contact` header for a normal extension number.
3.  **From Header:** Checks the `From` header if it does not look like a 12-character MAC address.

*Note: If the determined user part strictly matches a 12-character hexadecimal MAC address, the module will refuse to apply DND (so it doesn't pollute your AstDB with useless `DND/<mac>` entries), but it will still send a `200 OK` to stop the phone from retrying.*

---

## How it works

1.  **Registration Priority:** The module registers at `PJSIP_MOD_PRIORITY_TRANSPORT_LAYER + 1`. This safely intercepts the message before Asterisk attempts digest authentication, thereby avoiding infinite `401 Unauthorized` loops from mismatched MAC-to-Endpoint credentials.
2.  **Message Parsing:** It checks if the SIP method is `PUBLISH` and if the body is `application/pidf+xml` containing `<ce:dnd/>` or `<ce:available/>`.
3.  **State Application:**
    *   **DND ON:** Writes `"YES"` to `AstDB DND/<ext>` and sets the device state `Custom:DND<ext>` to `BUSY`.
    *   **DND OFF:** Deletes `AstDB DND/<ext>` and sets the device state `Custom:DND<ext>` to `NOT_INUSE`.
4.  **Response:** Sends a `200 OK` with `Expires: 2147483647` and a freshly generated `SIP-ETag`.

Because DND is written exactly like FreePBX natively does it, any Follow-Me, Call Forwarding, queue routing, and BLF hint (`hint => *78<ext>,Custom:DND<ext>`) will naturally respect the Cisco key.

---

## Troubleshooting

### Watch the live log

```bash
tail -f /var/log/asterisk/full | grep CiscoDND
```

A successful event produces:

```
[…] NOTICE[…] res_pjsip_cisco_dnd.c: CiscoDND: PUBLISH from endpoint '200' → extension '200' (DND ON)
[…] NOTICE[…] res_pjsip_cisco_dnd.c: CiscoDND: extension 200 DND ON (AstDB DND/<ext>=YES, devstate Custom:DND200=BUSY)
```

### Module complains it cannot determine extension

```
WARNING: CiscoDND: could not determine extension from PUBLISH (Contact/From look like MAC and no CISCO_DND_EXTEN set_var).
```
The phone sent its MAC address and the module couldn't find a real extension number.
**Fix:** Add `set_var = CISCO_DND_EXTEN=your_ext` to `/etc/asterisk/pjsip.endpoint_custom_post.conf` for that endpoint, as described in the Configuration section.

### `buildopts.h` checksum mismatch
If Asterisk refuses to load the module with a checksum error, re-extract the checksum:
```bash
strings /usr/lib/x86_64-linux-gnu/asterisk/modules/res_pjsip.so \
    | grep -E '^[a-f0-9]{32}$' | head -1
```
Update `buildopts.h` and recompile.

### See the raw SIP PUBLISH
```bash
asterisk -rx "pjsip set logger on"
```
Press the DND button on the phone and watch `/var/log/asterisk/full`. You should see the incoming `PUBLISH` request followed immediately by a `SIP/2.0 200 OK` generated by the module.
