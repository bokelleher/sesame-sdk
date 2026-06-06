// sesame.hpp: umbrella header for the SESAME C++ SDK.
//
// SESAME (Secure ESAM Authentication and Message Encryption) is the proposed
// SCTE 130-9 security layer for the ESAM interface. This is a native C++
// implementation of draft v0.5, proven byte-for-byte against the same golden
// vectors as the Rust crate and the deployed rust-pois reference.
#pragma once

#include "sesame/canonical.hpp"
#include "sesame/crypto.hpp"
#include "sesame/hex.hpp"
#include "sesame/keys.hpp"
#include "sesame/message.hpp"
#include "sesame/protocol.hpp"
#include "sesame/replay.hpp"
#include "sesame/tier1.hpp"
#include "sesame/tier3.hpp"
